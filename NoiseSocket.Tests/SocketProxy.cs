
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Noise.Tests
{
	internal sealed class SocketProxy
	{
		private readonly MemoryStream stream;
		private readonly ushort paddedLength;

		public SocketProxy(MemoryStream stream, ushort paddedLength)
		{
			this.stream = stream;
			this.paddedLength = paddedLength;
		}

		public List<Message> Messages { get; } = new List<Message>();

		public async Task WriteHandshakeMessageAsync(NoiseSocket socket, byte[] negotiationData, byte[] messageBody)
		{
			bool isNextMessageEncrypted = socket.IsNextMessageEncrypted;
			await socket.WriteHandshakeMessageAsync(negotiationData, messageBody, paddedLength);

			var message = new Message
			{
				NegotiationData = negotiationData != null ? Hex.Encode(negotiationData) : null,
				MessageBody = messageBody != null ? Hex.Encode(messageBody) : null,
				PaddedLength = isNextMessageEncrypted ? paddedLength : 0,
				Value = Utilities.ReadMessageHex(stream)
			};

			stream.Position = 0;
			Messages.Add(message);
		}

		public async Task WriteEmptyHandshakeMessageAsync(NoiseSocket socket, byte[] negotiationData)
		{
			await socket.WriteEmptyHandshakeMessageAsync(negotiationData);

			var message = new Message
			{
				NegotiationData = negotiationData != null ? Hex.Encode(negotiationData) : null,
				Value = Utilities.ReadMessageHex(stream)
			};

			stream.Position = 0;
			Messages.Add(message);
		}

		public async Task WriteMessageAsync(NoiseSocket socket, byte[] messageBody)
		{
			await socket.WriteMessageAsync(messageBody, paddedLength);

			var message = new Message
			{
				MessageBody = Hex.Encode(messageBody),
				PaddedLength = paddedLength,
				Value = Utilities.ReadMessageHex(stream)
			};

			stream.Position = 0;
			Messages.Add(message);
		}
	}
}
