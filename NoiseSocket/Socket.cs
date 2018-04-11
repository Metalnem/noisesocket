using System;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Noise
{
	internal sealed class Socket : IDisposable
	{
		private const int LenFieldSize = 2;
		private const int TagSize = 16;

		private Transport transport;
		private bool disposed;

		public byte[] WriteMessage(ReadOnlySpan<byte> messageBody, int paddedLen = 0)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException("Cannot call WriteMessage before the handshake has been completed.");
			}

			if (paddedLen > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Padded length must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			int unpaddedLen = LenFieldSize + messageBody.Length + TagSize;

			if (unpaddedLen > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			int noiseMessageLen = Math.Max(unpaddedLen, paddedLen);
			Debug.Assert(noiseMessageLen <= UInt16.MaxValue);

			var transportMessage = new byte[LenFieldSize + noiseMessageLen];
			var ciphertext = transportMessage.AsSpan().Slice(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage, (ushort)noiseMessageLen);
			BinaryPrimitives.WriteUInt16BigEndian(ciphertext, (ushort)messageBody.Length);
			messageBody.CopyTo(ciphertext.Slice(LenFieldSize));

			var payload = ciphertext.Slice(0, noiseMessageLen - TagSize);
			var written = transport.WriteMessage(payload, ciphertext);
			Debug.Assert(written == ciphertext.Length);

			return transportMessage;
		}

		public byte[] ReadMessage(ReadOnlySpan<byte> transportMessage)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException("Cannot call ReadMessage before the handshake has been completed.");
			}

			if (transportMessage.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			int minSize = LenFieldSize + LenFieldSize + TagSize;

			if (transportMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			var noiseMessageLen = BinaryPrimitives.ReadUInt16BigEndian(transportMessage);
			var noiseMessage = transportMessage.Slice(LenFieldSize);

			if (noiseMessageLen != noiseMessage.Length)
			{
				throw new ArgumentException("Invalid transport message length.");
			}

			Span<byte> plaintext = stackalloc byte[noiseMessageLen - TagSize];
			int read = transport.ReadMessage(noiseMessage, plaintext);
			Debug.Assert(read == plaintext.Length);

			var padded = plaintext.Slice(LenFieldSize);
			var bodyLen = BinaryPrimitives.ReadUInt16BigEndian(plaintext);

			if (bodyLen > padded.Length)
			{
				throw new ArgumentException("Invalid message body length.");
			}

			return padded.Slice(0, bodyLen).ToArray();
		}

		public void Dispose()
		{
			if (!disposed)
			{
				transport?.Dispose();
				disposed = true;
			}
		}
	}
}
