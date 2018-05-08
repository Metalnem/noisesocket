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

		[JsonProperty("alice_prologue")]
		public string AlicePrologue;

		[JsonProperty("alice_psks")]
		public List<string> AlicePsks;

		[JsonProperty("bob_prologue")]
		public string BobPrologue;

		[JsonProperty("bob_psks")]
		public List<string> BobPsks;

		[JsonProperty("handshake_hash")]
		public string HandshakeHash;

		[JsonProperty("messages")]
		public List<Message> Messages;
	}
}
