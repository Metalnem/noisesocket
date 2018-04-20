using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Noise
{
	/// <summary>
	/// NoiseSocket provides an encoding layer for the Noise Protocol
	/// Framework. NoiseSocket can encode Noise messages and associated
	/// negotiation data into a form suitable for transmission over
	/// reliable, stream-based protocols such as TCP.
	/// </summary>
	public sealed class NoiseSocket : IDisposable
	{
		private const int LenFieldSize = 2;
		private const int TagSize = 16;

		private static readonly byte[] noiseSocketInit1 = Encoding.UTF8.GetBytes("NoiseSocketInit1");
		private static readonly byte[] noiseSocketInit2 = Encoding.UTF8.GetBytes("NoiseSocketInit2");

		private readonly Func<byte[], HandshakeState> initializer;
		private HandshakeState handshakeState;
		private Transport transport;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="initiator">A boolean indicating the initiator or responder role.</param>
		/// <param name="s">The local static private key (optional).</param>
		/// <param name="rs">The remote party's static public key (optional).</param>
		/// <param name="psks">The collection of zero or more 32-byte pre-shared secret keys.</param>
		/// <exception cref="ArgumentNullException">
		/// Thrown if the <paramref name="protocol"/> is null.
		/// </exception>
		public NoiseSocket(
			Protocol protocol,
			bool initiator,
			byte[] s = default,
			byte[] rs = default,
			IEnumerable<byte[]> psks = default)
		{
			ThrowIfNull(protocol, nameof(protocol));

			initializer = prologue => protocol.Create(initiator, prologue, s, rs, psks);
		}

		public async Task WriteHandshakeMessageAsync(
			Stream stream,
			Memory<byte> negotiationData,
			Memory<byte> messageBody = default,
			ushort paddedLength = default,
			CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (this.transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteHandshakeMessageAsync)} after the handshake has been completed.");
			}

			if (negotiationData.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Negotiation data must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			if (messageBody.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Handshake message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			InitializeHandshakeState(negotiationData.Span);

			// negotiation_data_len (2 bytes)
			// negotiation_data
			// noise_message_len (2 bytes)
			// noise_message

			int negotiationLength = LenFieldSize + negotiationData.Length;
			int maxNoiseLength = LenFieldSize + Protocol.MaxMessageLength;

			// Prevent the buffer from going to the LOH (it may be greater than 85000 bytes).
			var pool = ArrayPool<byte>.Shared;
			var buffer = pool.Rent(negotiationLength + maxNoiseLength);

			try
			{
				var plaintext = WritePacket(messageBody.Span);
				var (written, hash, transport) = handshakeState.WriteMessage(plaintext, buffer.AsSpan(negotiationLength + LenFieldSize));

				if (transport != null)
				{
					handshakeState.Dispose();
					handshakeState = null;

					this.transport = transport;
				}

				WritePacket(negotiationData.Span, buffer);
				BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(negotiationLength), (ushort)written);

				int noiseLength = LenFieldSize + written;
				int handshakeLength = negotiationLength + noiseLength;

				await stream.WriteAsync(buffer, 0, handshakeLength, cancellationToken).ConfigureAwait(false);
			}
			finally
			{
				pool.Return(buffer);
			}
		}

		public async Task<byte[]> ReadNegotiationDataAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadNegotiationDataAsync)} after the handshake has been completed.");
			}

			var negotiationData = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			InitializeHandshakeState(negotiationData);

			return negotiationData;
		}

		public async Task<byte[]> ReadHandshakeMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (this.transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadHandshakeMessageAsync)} after the handshake has been completed.");
			}

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			var minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Handshake message must be greater than or equal to {minSize} bytes in length.");
			}

			var plaintext = new byte[noiseMessage.Length];
			var (read, hash, transport) = handshakeState.ReadMessage(noiseMessage, plaintext);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			return ReadPacket(plaintext.AsSpan(0, read));
		}

		public Task WriteMessageAsync(
			Stream stream,
			Memory<byte> messageBody,
			ushort paddedLength = default,
			CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteMessageAsync)} before the handshake has been completed.");
			}

			int unpaddedLength = LenFieldSize + messageBody.Length + TagSize;

			if (unpaddedLength > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			var noiseMessageLength = Math.Max(unpaddedLength, paddedLength);
			var transportMessage = new byte[LenFieldSize + noiseMessageLength];
			var ciphertext = transportMessage.AsMemory(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage.AsSpan(), (ushort)noiseMessageLength);
			BinaryPrimitives.WriteUInt16BigEndian(ciphertext.Span, (ushort)messageBody.Length);
			messageBody.CopyTo(ciphertext.Slice(LenFieldSize));

			var payload = ciphertext.Slice(0, noiseMessageLength - TagSize);
			var written = transport.WriteMessage(payload.Span, ciphertext.Span);

			return stream.WriteAsync(transportMessage, 0, transportMessage.Length, cancellationToken);
		}

		public async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadMessageAsync)} before the handshake has been completed.");
			}

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			var minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			var read = transport.ReadMessage(noiseMessage, noiseMessage);

			return ReadPacket(noiseMessage.AsSpan(0, read));
		}

		private void InitializeHandshakeState(ReadOnlySpan<byte> negotiationMessage)
		{
			if (handshakeState == null)
			{
				byte[] prologue = new byte[noiseSocketInit1.Length + LenFieldSize + negotiationMessage.Length];

				noiseSocketInit1.AsSpan().CopyTo(prologue);
				WritePacket(negotiationMessage, prologue.AsSpan(noiseSocketInit1.Length));

				handshakeState = initializer(prologue);
			}
		}

		private void ThrowIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(NoiseSocket));
			}
		}

		private static void ThrowIfNull(object value, string name)
		{
			if (value == null)
			{
				throw new ArgumentNullException(name);
			}
		}

		private static void WritePacket(ReadOnlySpan<byte> data, Span<byte> message)
		{
			int length = data.Length;
			Debug.Assert(length < UInt16.MaxValue);
			Debug.Assert(LenFieldSize + length <= message.Length);

			BinaryPrimitives.WriteUInt16BigEndian(message, (ushort)length);
			data.CopyTo(message.Slice(LenFieldSize));
		}

		private static byte[] WritePacket(ReadOnlySpan<byte> data)
		{
			int length = data.Length;
			Debug.Assert(length < UInt16.MaxValue);

			byte[] message = new byte[LenFieldSize + length];
			WritePacket(data, message);

			return message;
		}

		private static byte[] ReadPacket(ReadOnlySpan<byte> packet)
		{
			if (packet.Length < LenFieldSize)
			{
				throw new ArgumentException($"Packet must be greater than or equal to {LenFieldSize} bytes in length.");
			}

			var length = BinaryPrimitives.ReadUInt16BigEndian(packet);
			var data = packet.Slice(LenFieldSize);

			if (length > data.Length)
			{
				throw new ArgumentException("Invalid message body length.");
			}

			return data.Slice(0, length).ToArray();
		}

		private static async Task<byte[]> ReadPacketAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			byte[] lengthBuffer = new byte[LenFieldSize];
			await stream.ReadAsync(lengthBuffer, 0, lengthBuffer.Length, cancellationToken).ConfigureAwait(false);

			byte[] data = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer)];
			await stream.ReadAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);

			return data;
		}

		/// <summary>
		/// Releases all resources used by the current
		/// instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				handshakeState?.Dispose();
				transport?.Dispose();
				disposed = true;
			}
		}
	}
}
