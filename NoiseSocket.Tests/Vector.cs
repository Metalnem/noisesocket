using System.Collections.Generic;
using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Vector
	{
		[JsonProperty("protocol_name")]
		public string ProtocolName;

		[JsonProperty("init_prologue")]
		public string InitPrologue;

		[JsonProperty("init_static")]
		public string InitStatic;

		[JsonProperty("init_ephemeral")]
		public string InitEphemeral;

		[JsonProperty("init_remote_static")]
		public string InitRemoteStatic;

		[JsonProperty("resp_prologue")]
		public string RespPrologue;

		[JsonProperty("resp_static")]
		public string RespStatic;

		[JsonProperty("resp_ephemeral")]
		public string RespEphemeral;

		[JsonProperty("resp_remote_static")]
		public string RespRemoteStatic;

		[JsonProperty("handshake_hash")]
		public string HandshakeHash;

		[JsonProperty("messages")]
		public List<Message> Messages;
	}
}
