using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Message
	{
		[JsonProperty("negotiation_data")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] NegotiationData;

		[JsonProperty("message_body")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] MessageBody;

		[JsonProperty("padded_length")]
		public ushort PaddedLength;

		[JsonProperty("message")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] Value;
	}
}
