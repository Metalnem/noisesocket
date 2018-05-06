using System.Collections.Generic;
using Newtonsoft.Json;

namespace Noise.Tests
{
	internal sealed class Vector
	{
		[JsonProperty("initial")]
		public Config Initial;

		[JsonProperty("switch")]
		public Config Switch;

		[JsonProperty("retry")]
		public Config Retry;

		[JsonProperty("init_prologue")]
		public string InitPrologue;

		[JsonProperty("resp_prologue")]
		public string RespPrologue;

		[JsonProperty("handshake_hash")]
		public string HandshakeHash;

		[JsonProperty("messages")]
		public List<Message> Messages;
	}
}
