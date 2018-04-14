using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Noise
{
	internal sealed class Socket : IDisposable
	{
		private const int LenFieldSize = 2;
		private const int TagSize = 16;

		private HandshakeState handshakeState;
		private Transport transport;
		private bool disposed;

		public Socket(
			Protocol protocol,
			bool initiator,
			byte[] prologue = default,
			byte[] s = default,
			byte[] rs = default,
			IEnumerable<byte[]> psks = default)
		{
			Exceptions.ThrowIfNull(protocol, nameof(protocol));

			handshakeState = protocol.Create(initiator, prologue, s, rs, psks);
		}

		public async Task WriteHandshakeMessageAsync(
			Stream stream,
			Memory<byte> negotiationData,
			Memory<byte> messageBody,
			CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (handshakeState == null)
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

			Memory<byte> plaintext = WritePacket(messageBody);
			Memory<byte> ciphertext = new byte[LenFieldSize + Protocol.MaxMessageLength];

			var (written, hash, transport) = handshakeState.WriteMessage(plaintext.Span, ciphertext.Slice(LenFieldSize).Span);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			var negotiationMessage = WritePacket(negotiationData);
			await stream.WriteAsync(negotiationMessage, 0, negotiationMessage.Length, cancellationToken).ConfigureAwait(false);

			var noiseMessage = WritePacket(ciphertext.Slice(0, LenFieldSize + written));
			await stream.WriteAsync(noiseMessage, 0, noiseMessage.Length, cancellationToken).ConfigureAwait(false);
		}

		public Task<byte[]> PeekHandshakeMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (handshakeState == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(PeekHandshakeMessageAsync)} after the handshake has been completed.");
			}

			return ReadPacketAsync(stream, cancellationToken);
		}

		public async Task<byte[]> ReadHandshakeMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (handshakeState == null)
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

			return ReadPacket(plaintext.AsReadOnlySpan().Slice(0, read));
		}

		public Task WriteMessageAsync(
			Stream stream,
			Memory<byte> messageBody,
			ushort paddedLen = 0,
			CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteMessageAsync)} before the handshake has been completed.");
			}

			int unpaddedLen = LenFieldSize + messageBody.Length + TagSize;

			if (unpaddedLen > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			var noiseMessageLen = Math.Max(unpaddedLen, paddedLen);
			var transportMessage = new byte[LenFieldSize + noiseMessageLen];
			var ciphertext = new Memory<byte>(transportMessage).Slice(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage.AsSpan(), (ushort)noiseMessageLen);
			BinaryPrimitives.WriteUInt16BigEndian(ciphertext.Span, (ushort)messageBody.Length);
			messageBody.CopyTo(ciphertext.Slice(LenFieldSize));

			var payload = ciphertext.Slice(0, noiseMessageLen - TagSize);
			var written = transport.WriteMessage(payload.Span, ciphertext.Span);

			return stream.WriteAsync(transportMessage, 0, transportMessage.Length, cancellationToken);
		}

		public async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadMessageAsync)} before the handshake has been completed.");
			}

			Memory<byte> noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			int minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			var read = transport.ReadMessage(noiseMessage.Span, noiseMessage.Span);
			var plaintext = noiseMessage.Slice(0, read);

			return ReadPacket(plaintext.Span);
		}

		private static byte[] WritePacket(Memory<byte> data)
		{
			int length = data.Length;
			Debug.Assert(length < UInt16.MaxValue);

			byte[] message = new byte[LenFieldSize + length];
			BinaryPrimitives.WriteUInt16BigEndian(message, (ushort)length);
			data.Span.CopyTo(message.AsSpan().Slice(LenFieldSize));

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

			var data = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBuffer)];
			await stream.ReadAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);

			return data;
		}

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
