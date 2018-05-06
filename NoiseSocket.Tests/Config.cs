using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Config
	{
		[JsonProperty("protocol_name")]
		public string ProtocolName;

		[JsonProperty("alice_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] AliceStatic;

		[JsonProperty("alice_ephemeral")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] AliceEphemeral;

		[JsonProperty("alice_remote_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] AliceRemoteStatic;

		[JsonProperty("bob_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] BobStatic;

		[JsonProperty("bob_ephemeral")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] BobEphemeral;

		[JsonProperty("bob_remote_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] BobRemoteStatic;
	}
}
