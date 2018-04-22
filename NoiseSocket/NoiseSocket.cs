using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

		private readonly Protocol protocol;
		private readonly ProtocolConfig config;
		private readonly Stream stream;
		private readonly bool leaveOpen;

		private HandshakeState handshakeState;
		private Transport transport;
		private bool isNextMessageEncrypted;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="config">
		/// A set of parameters used to instantiate an initial <see cref="HandshakeState"/>.
		/// </param>
		/// <param name="stream">The stream for reading and writing encoded protocol messages.</param>
		/// <param name="leaveOpen">
		/// True to leave the stream open after the
		/// <see cref="NoiseSocket"/> object is disposed, false otherwise.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/>,
		/// <paramref name="config"/>, or <paramref name="stream"/> is null.
		/// </exception>
		public NoiseSocket(Protocol protocol, ProtocolConfig config, Stream stream, bool leaveOpen = false)
		{
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));
			ThrowIfNull(stream, nameof(stream));

			this.protocol = protocol;
			this.config = config;
			this.stream = stream;
			this.leaveOpen = leaveOpen;

			isNextMessageEncrypted = IsInitialMessageEncrypted(protocol);
		}

		/// <summary>
		/// Asynchronously writes the negotiation data and the handshake message to the input stream.
		/// </summary>
		/// <param name="negotiationData">The negotiation data.</param>
		/// <param name="messageBody">The message body to encrypt.</param>
		/// <param name="paddedLength">
		/// If this message has an encrypted payload and the length of the
		/// <paramref name="messageBody"/> is less than <paramref name="paddedLength"/>,
		/// <paramref name="messageBody"/> is padded to make its
		/// length equal to <paramref name="paddedLength"/>.
		/// </param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the output stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to <see cref="ReadHandshakeMessageAsync"/> was expected
		/// or the handshake has already been completed.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the Noise message was greater than
		/// <see cref="Protocol.MaxMessageLength"/> bytes in length.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task WriteHandshakeMessageAsync(
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
				Memory<byte> plaintext = messageBody;

				if (isNextMessageEncrypted)
				{
					plaintext = new byte[LenFieldSize + Math.Max(messageBody.Length, paddedLength)];
					WritePacket(messageBody.Span, plaintext.Span);
				}

				var (written, hash, transport) = handshakeState.WriteMessage(plaintext.Span, buffer.AsSpan(negotiationLength + LenFieldSize));
				isNextMessageEncrypted = true;

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

		/// <summary>
		/// Asynchronously reads the negotiation data from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the negotiation data.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has already been completed.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task<byte[]> ReadNegotiationDataAsync(CancellationToken cancellationToken = default)
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

		/// <summary>
		/// Asynchronously reads the handshake message from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the decrypted message body.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to <see cref="WriteHandshakeMessageAsync"/>
		/// was expected or the handshake has already been completed.
		/// </exception>
		/// <exception cref="System.Security.Cryptography.CryptographicException">
		/// Thrown if the decryption of the message has failed.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task<byte[]> ReadHandshakeMessageAsync(CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (this.transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadHandshakeMessageAsync)} after the handshake has been completed.");
			}

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			var plaintext = new byte[noiseMessage.Length];
			var (read, hash, transport) = handshakeState.ReadMessage(noiseMessage, plaintext);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			if (isNextMessageEncrypted)
			{
				return ReadPacket(plaintext.AsSpan(0, read));
			}

			isNextMessageEncrypted = true;
			return plaintext.AsSpan(0, read).ToArray();
		}

		/// <summary>
		/// Asynchronously writes the transport message to the input stream.
		/// </summary>
		/// <param name="messageBody">The message body to encrypt.</param>
		/// <param name="paddedLength">
		/// If the length of the <paramref name="messageBody"/> is less than
		/// <paramref name="paddedLength"/>, <paramref name="messageBody"/>
		/// is padded to make its length equal to <paramref name="paddedLength"/>.
		/// </param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the output stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has not yet been completed, or the
		/// responder has attempted to write a message to a one-way stream.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the encrypted payload was greater than
		/// <see cref="Protocol.MaxMessageLength"/> bytes in length.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support writing.</exception>
		public Task WriteMessageAsync(
			Memory<byte> messageBody,
			ushort paddedLength = default,
			CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteMessageAsync)} before the handshake has been completed.");
			}

			int length = Math.Max(messageBody.Length, paddedLength);
			int noiseMessageLength = LenFieldSize + length + TagSize;

			if (noiseMessageLength > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			var transportMessage = new byte[LenFieldSize + noiseMessageLength];
			var ciphertext = transportMessage.AsMemory(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage.AsSpan(), (ushort)noiseMessageLength);
			WritePacket(messageBody.Span, ciphertext.Span);

			var payload = ciphertext.Slice(0, noiseMessageLength - TagSize);
			var written = transport.WriteMessage(payload.Span, ciphertext.Span);

			return stream.WriteAsync(transportMessage, 0, transportMessage.Length, cancellationToken);
		}

		/// <summary>
		/// Asynchronously reads the transport message from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the decrypted message body.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has not yet been completed, or the
		/// initiator has attempted to read a message from a one-way stream.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the message was greater than <see cref="Protocol.MaxMessageLength"/>
		/// bytes in length, or the decrypted message body length was invalid.
		/// </exception>
		/// <exception cref="System.Security.Cryptography.CryptographicException">
		/// Thrown if the decryption of the message has failed.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task<byte[]> ReadMessageAsync(CancellationToken cancellationToken = default)
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

				config.Prologue = prologue;
				handshakeState = protocol.Create(config);
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

		private static byte[] ReadPacket(ReadOnlySpan<byte> packet)
		{
			Debug.Assert(packet.Length <= UInt16.MaxValue);

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
			byte[] length = new byte[LenFieldSize];
			await stream.ReadAsync(length, 0, length.Length, cancellationToken).ConfigureAwait(false);

			byte[] data = new byte[BinaryPrimitives.ReadUInt16BigEndian(length)];
			await stream.ReadAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);

			return data;
		}

		private static bool IsInitialMessageEncrypted(Protocol protocol)
		{
			var psks = PatternModifiers.Psk0 | PatternModifiers.Psk1 | PatternModifiers.Psk2 | PatternModifiers.Psk3;

			if ((protocol.Modifiers & psks) != 0)
			{
				return true;
			}

			foreach (var token in protocol.HandshakePattern.Patterns.First().Tokens)
			{
				switch (token)
				{
					case Token.EE:
					case Token.ES:
					case Token.SE:
					case Token.SS: return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Releases all resources used by the current
		/// instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				if (!leaveOpen)
				{
					stream.Dispose();
				}

				handshakeState?.Dispose();
				transport?.Dispose();

				disposed = true;
			}
		}
	}
}
