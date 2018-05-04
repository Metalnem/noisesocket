using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Message
	{
		[JsonProperty("payload")]
		public string Payload;

		[JsonProperty("ciphertext")]
		public string Ciphertext;
	}
}
