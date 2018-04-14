using System;
using System.Buffers.Binary;
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

		public async Task WriteHandshakeMessageAsync(
			Stream stream,
			Memory<byte> negotiationData,
			Memory<byte> messageBody,
			CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (handshakeState == null)
			{
				throw new InvalidOperationException("Cannot call WriteHandshakeMessage after the handshake has been completed.");
			}

			if (negotiationData.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Negotiation data must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			if (messageBody.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Handshake message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			Memory<byte> plaintext = PrependLength(messageBody);
			Memory<byte> ciphertext = new byte[LenFieldSize + Protocol.MaxMessageLength];

			var (written, hash, transport) = handshakeState.WriteMessage(plaintext.Span, ciphertext.Slice(LenFieldSize).Span);
			Debug.Assert(written >= plaintext.Length);
			Debug.Assert(written <= Protocol.MaxMessageLength);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			var negotiationMessage = PrependLength(negotiationData);
			await stream.WriteAsync(negotiationMessage, cancellationToken).ConfigureAwait(false);

			var noiseMessage = PrependLength(ciphertext.Slice(0, LenFieldSize + written));
			await stream.WriteAsync(noiseMessage, cancellationToken).ConfigureAwait(false);
		}

		public async Task WriteMessageAsync(
			Stream stream,
			Memory<byte> messageBody,
			ushort paddedLen = 0,
			CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException("Cannot call WriteMessage before the handshake has been completed.");
			}

			int unpaddedLen = LenFieldSize + messageBody.Length + TagSize;

			if (unpaddedLen > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			int noiseMessageLen = Math.Max(unpaddedLen, paddedLen);
			Memory<byte> transportMessage = new byte[LenFieldSize + noiseMessageLen];
			Memory<byte> ciphertext = transportMessage.Slice(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage.Span, (ushort)noiseMessageLen);
			BinaryPrimitives.WriteUInt16BigEndian(ciphertext.Span, (ushort)messageBody.Length);
			messageBody.CopyTo(ciphertext.Slice(LenFieldSize));

			var payload = ciphertext.Slice(0, noiseMessageLen - TagSize);
			var written = transport.WriteMessage(payload.Span, ciphertext.Span);
			Debug.Assert(written == ciphertext.Length);

			await stream.WriteAsync(transportMessage, cancellationToken).ConfigureAwait(false);
		}

		public async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException("Cannot call ReadMessage before the handshake has been completed.");
			}

			Memory<byte> lenBuffer = new byte[LenFieldSize];
			await stream.ReadAsync(lenBuffer, cancellationToken).ConfigureAwait(false);

			var noiseMessageLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuffer.Span);
			var minSize = LenFieldSize + TagSize;

			if (noiseMessageLen < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			Memory<byte> noiseMessage = new byte[noiseMessageLen];
			int read = transport.ReadMessage(noiseMessage.Span, noiseMessage.Span);
			Debug.Assert(read == noiseMessageLen - TagSize);

			var plaintext = noiseMessage.Slice(0, read);
			var bodyLen = BinaryPrimitives.ReadUInt16BigEndian(plaintext.Span);
			var padded = plaintext.Slice(LenFieldSize);

			if (bodyLen > padded.Length)
			{
				throw new ArgumentException("Invalid message body length.");
			}

			return padded.Slice(0, bodyLen).ToArray();
		}

		private static Memory<byte> PrependLength(Memory<byte> data)
		{
			int length = data.Length;
			Debug.Assert(length < UInt16.MaxValue);

			Memory<byte> message = new byte[LenFieldSize + length];
			BinaryPrimitives.WriteUInt16BigEndian(message.Span, (ushort)length);
			data.CopyTo(message.Slice(LenFieldSize));

			return message;
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
