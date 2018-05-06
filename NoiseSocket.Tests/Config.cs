using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Config
	{
		[JsonProperty("protocol_name")]
		public string ProtocolName;

		[JsonProperty("init_static")]
		public string InitStatic;

		[JsonProperty("init_ephemeral")]
		public string InitEphemeral;

		[JsonProperty("init_remote_static")]
		public string InitRemoteStatic;

		[JsonProperty("resp_static")]
		public string RespStatic;

		[JsonProperty("resp_ephemeral")]
		public string RespEphemeral;

		[JsonProperty("resp_remote_static")]
		public string RespRemoteStatic;
	}
}
