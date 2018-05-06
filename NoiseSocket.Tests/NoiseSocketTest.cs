using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class NoiseSocketTest
	{
		[Fact]
		public async Task TestVectors()
		{
			var s = File.ReadAllText("Vectors/noisesocket.json");
			var json = JObject.Parse(s);

			using (var stream = new MemoryStream())
			{
				foreach (var vector in json["vectors"])
				{
					var initialConfig = vector["initial"];
					var switchConfig = vector["switch"];
					var retryConfig = vector["retry"];

					var alicePrologue = GetBytes(vector, "alice_prologue");
					var bobPrologue = GetBytes(vector, "bob_prologue");
					var handshakeHash = GetBytes(vector, "handshake_hash");

					var config = vector["initial"].ToObject<Config>();
					var aliceConfig = new ProtocolConfig(true, alicePrologue, config.AliceStatic, config.AliceRemoteStatic);
					var bobConfig = new ProtocolConfig(false, bobPrologue, config.BobStatic, config.BobRemoteStatic);

					var protocol = Protocol.Parse(config.ProtocolName.AsSpan());
					var queue = ReadMessages(vector["messages"]);

					var alice = NoiseSocket.CreateClient(protocol, aliceConfig, stream, true);
					var bob = NoiseSocket.CreateServer(stream, true);

					var aliceEphemeral = config.AliceEphemeral;
					var bobEphemeral = config.BobEphemeral;

					alice.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, aliceEphemeral));
					bob.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, bobEphemeral));

					var writer = alice;
					var reader = bob;

					if (switchConfig == null && retryConfig == null)
					{
						var message = queue.Dequeue();
						stream.Position = 0;

						await alice.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData, await bob.ReadNegotiationDataAsync());

						bob.Accept(protocol, bobConfig);
						Assert.Equal(message.MessageBody, await bob.ReadHandshakeMessageAsync());

						Utilities.Swap(ref writer, ref reader);
					}
					else if (switchConfig != null)
					{
						config = switchConfig.ToObject<Config>();
						protocol = Protocol.Parse(config.ProtocolName.AsSpan());

						aliceConfig = new ProtocolConfig(false, alicePrologue, config.AliceStatic, config.AliceRemoteStatic);
						bobConfig = new ProtocolConfig(true, bobPrologue, config.BobStatic, config.BobRemoteStatic);

						var message = queue.Dequeue();
						stream.Position = 0;

						await alice.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData, await bob.ReadNegotiationDataAsync());

						bob.Switch(protocol, bobConfig);
						bob.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.BobEphemeral));
						await bob.IgnoreHandshakeMessageAsync();

						message = queue.Dequeue();
						stream.Position = 0;

						await bob.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData, await alice.ReadNegotiationDataAsync());

						alice.Switch(protocol, aliceConfig);
						alice.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.AliceEphemeral));
						Assert.Equal(message.MessageBody, await alice.ReadHandshakeMessageAsync());
					}
					else if (retryConfig != null)
					{
						config = retryConfig.ToObject<Config>();
						protocol = Protocol.Parse(config.ProtocolName.AsSpan());

						aliceConfig = new ProtocolConfig(true, alicePrologue, config.AliceStatic, config.AliceRemoteStatic);
						bobConfig = new ProtocolConfig(false, bobPrologue, config.BobStatic, config.BobRemoteStatic);

						var message = queue.Dequeue();
						stream.Position = 0;

						await alice.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData, await bob.ReadNegotiationDataAsync());

						bob.Retry(protocol, bobConfig);
						bob.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.BobEphemeral));
						await bob.IgnoreHandshakeMessageAsync();

						message = queue.Dequeue();
						stream.Position = 0;

						await bob.WriteEmptyHandshakeMessageAsync(message.NegotiationData);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData, await alice.ReadNegotiationDataAsync());

						alice.Retry(protocol, aliceConfig);
						alice.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.AliceEphemeral));
						await alice.IgnoreHandshakeMessageAsync();
					}

					while (queue.Count > 0)
					{
						var message = queue.Dequeue();

						if (writer.HandshakeHash.IsEmpty)
						{
							stream.Position = 0;
							await writer.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
							Assert.Equal(message.Value, Utilities.ReadMessage(stream));

							stream.Position = 0;
							Assert.Empty(await reader.ReadNegotiationDataAsync());
							Assert.Equal(message.MessageBody, await reader.ReadHandshakeMessageAsync());
						}
						else
						{
							stream.Position = 0;
							await writer.WriteMessageAsync(message.MessageBody, message.PaddedLength);
							Assert.Equal(message.Value, Utilities.ReadMessage(stream));

							stream.Position = 0;
							Assert.Equal(message.MessageBody, await reader.ReadMessageAsync());
						}

						Utilities.Swap(ref writer, ref reader);
					}

					Assert.Equal(handshakeHash, writer.HandshakeHash.ToArray());
					Assert.Equal(handshakeHash, reader.HandshakeHash.ToArray());

					alice.Dispose();
					bob.Dispose();
				}
			}
		}

		private static string GetString(JToken token, string property)
		{
			return (string)token[property] ?? String.Empty;
		}

		private static byte[] GetBytes(JToken token, string property)
		{
			return Hex.Decode(GetString(token, property));
		}

		private static Queue<Message> ReadMessages(JToken messages)
		{
			var queue = new Queue<Message>();

			foreach (var message in messages)
			{
				queue.Enqueue(message.ToObject<Message>());
			}

			return queue;
		}
	}
}
