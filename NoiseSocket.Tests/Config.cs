using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Config
	{
		[JsonProperty("protocol_name")]
		public string ProtocolName;

		[JsonProperty("init_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] InitStatic;

		[JsonProperty("init_ephemeral")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] InitEphemeral;

		[JsonProperty("init_remote_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] InitRemoteStatic;

		[JsonProperty("resp_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] RespStatic;

		[JsonProperty("resp_ephemeral")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] RespEphemeral;

		[JsonProperty("resp_remote_static")]
		[JsonConverter(typeof(ByteArrayConverter))]
		public byte[] RespRemoteStatic;
	}
}
