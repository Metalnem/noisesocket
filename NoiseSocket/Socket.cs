using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Noise
{
	internal sealed class Socket : IDisposable
	{
		private const int LenFieldSize = 2;
		private const int TagSize = 16;

		private HandshakeState handshakeState;
		private Transport transport;
		private bool disposed;

		public void WriteHandshakeMessage(Stream stream, ReadOnlySpan<byte> negotiationData, ReadOnlySpan<byte> messageBody)
		{
			byte[] message = WriteHandshakeMessage(negotiationData, messageBody);
			stream.Write(message, 0, message.Length);
		}

		private byte[] WriteHandshakeMessage(ReadOnlySpan<byte> negotiationData, ReadOnlySpan<byte> messageBody)
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

			Span<byte> noiseMessage = new byte[LenFieldSize + messageBody.Length];
			BinaryPrimitives.WriteUInt16BigEndian(noiseMessage, (ushort)messageBody.Length);
			messageBody.CopyTo(noiseMessage.Slice(LenFieldSize));

			var buffer = new byte[Protocol.MaxMessageLength];
			var (written, hash, transport) = handshakeState.WriteMessage(noiseMessage, buffer);
			Debug.Assert(written <= Protocol.MaxMessageLength);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			byte[] handshakeMessage = new byte[LenFieldSize + negotiationData.Length + LenFieldSize + written];

			Span<byte> negotiationDataPart = handshakeMessage.AsSpan().Slice(0, LenFieldSize + negotiationData.Length);
			BinaryPrimitives.WriteUInt16BigEndian(negotiationDataPart, (ushort)negotiationData.Length);
			negotiationData.CopyTo(negotiationDataPart.Slice(LenFieldSize));

			Span<byte> messageBodyPart = handshakeMessage.AsSpan().Slice(negotiationDataPart.Length);
			BinaryPrimitives.WriteUInt16BigEndian(messageBodyPart, (ushort)written);
			buffer.AsSpan().Slice(0, written).CopyTo(messageBodyPart.Slice(LenFieldSize));

			return handshakeMessage;
		}

		public void WriteMessage(Stream stream, ReadOnlySpan<byte> messageBody, ushort paddedLen = 0)
		{
			byte[] message = WriteMessage(messageBody, paddedLen);
			stream.Write(message, 0, message.Length);
		}

		private byte[] WriteMessage(ReadOnlySpan<byte> messageBody, ushort paddedLen)
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

		public byte[] ReadMessage(Stream stream)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(Socket));

			if (transport == null)
			{
				throw new InvalidOperationException("Cannot call ReadMessage before the handshake has been completed.");
			}

			using (var reader = new BinaryReader(stream, Encoding.ASCII, true))
			{
				var noiseMessageLen = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
				var noiseMessage = reader.ReadBytes(noiseMessageLen);

				return ReadMessage(noiseMessage);
			}
		}

		private byte[] ReadMessage(byte[] noiseMessage)
		{
			int minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			int read = transport.ReadMessage(noiseMessage, noiseMessage);
			Debug.Assert(read == noiseMessage.Length - TagSize);

			var plaintext = noiseMessage.AsSpan().Slice(read);
			var bodyLen = BinaryPrimitives.ReadUInt16BigEndian(plaintext);
			var padded = plaintext.Slice(LenFieldSize);

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
				handshakeState?.Dispose();
				transport?.Dispose();
				disposed = true;
			}
		}
	}
}
