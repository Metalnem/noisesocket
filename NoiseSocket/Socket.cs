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

			byte[] transportMessage = new byte[LenFieldSize + noiseMessageLen];
			Span<byte> noiseMessage = transportMessage.AsSpan().Slice(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage, (ushort)noiseMessageLen);
			BinaryPrimitives.WriteUInt16BigEndian(noiseMessage, (ushort)messageBody.Length);
			messageBody.CopyTo(noiseMessage.Slice(LenFieldSize));

			var payload = noiseMessage.Slice(0, noiseMessageLen - TagSize);
			var written = transport.WriteMessage(payload, noiseMessage);

			Debug.Assert(written == noiseMessageLen);

			return transportMessage;
		}

		public byte[] ReadMessage(ReadOnlySpan<byte> transportMessage)
		{
			throw new NotImplementedException();
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
