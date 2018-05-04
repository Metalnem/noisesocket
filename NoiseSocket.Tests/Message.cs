using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Message
	{
		[JsonProperty("negotiation_data")]
		public string NegotiationData;

		[JsonProperty("payload")]
		public string Payload;

		[JsonProperty("ciphertext")]
		public string Ciphertext;
	}
}
