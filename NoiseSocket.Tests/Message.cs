using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Message
	{
		[JsonProperty("negotiation_data")]
		public string NegotiationData;

		[JsonProperty("message_body")]
		public string MessageBody;

		[JsonProperty("padded_length")]
		public int? PaddedLength;

		[JsonProperty("message")]
		public string Value;
	}
}
