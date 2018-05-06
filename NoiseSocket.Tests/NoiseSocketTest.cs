using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class NoiseSocketTest
	{
		private static readonly byte[] empty = Array.Empty<byte>();

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

					var initPrologue = GetBytes(vector, "init_prologue");
					var respPrologue = GetBytes(vector, "resp_prologue");
					var handshakeHash = GetBytes(vector, "handshake_hash");

					var config = vector["initial"].ToObject<Config>();
					var initConfig = new ProtocolConfig(true, initPrologue, config.InitStatic, config.InitRemoteStatic);
					var respConfig = new ProtocolConfig(false, respPrologue, config.RespStatic, config.RespRemoteStatic);

					var protocol = Protocol.Parse(config.ProtocolName.AsSpan());
					var queue = ReadMessages(vector["messages"]);

					var initSocket = NoiseSocket.CreateClient(protocol, initConfig, stream, true);
					var respSocket = NoiseSocket.CreateServer(stream, true);

					initSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.InitEphemeral.ToArray()));
					respSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, config.RespEphemeral.ToArray()));

					var writer = initSocket;
					var reader = respSocket;

					if (switchConfig == null && retryConfig == null)
					{
						var message = queue.Dequeue();
						stream.Position = 0;

						await initSocket.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData ?? empty, await respSocket.ReadNegotiationDataAsync());

						respSocket.Accept(protocol, respConfig);
						Assert.Equal(message.MessageBody, await respSocket.ReadHandshakeMessageAsync());

						Utilities.Swap(ref writer, ref reader);
					}
					else if (retryConfig != null)
					{
						config = retryConfig.ToObject<Config>();
						protocol = Protocol.Parse(config.ProtocolName.AsSpan());

						initConfig = new ProtocolConfig(true, initPrologue, config.InitStatic, config.InitRemoteStatic);
						respConfig = new ProtocolConfig(false, respPrologue, config.RespStatic, config.RespRemoteStatic);

						var message = queue.Dequeue();
						stream.Position = 0;

						await initSocket.WriteHandshakeMessageAsync(message.NegotiationData, message.MessageBody, message.PaddedLength);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData ?? empty, await respSocket.ReadNegotiationDataAsync());

						respSocket.Retry(protocol, respConfig);
						await respSocket.IgnoreHandshakeMessageAsync();

						message = queue.Dequeue();
						stream.Position = 0;

						await respSocket.WriteEmptyHandshakeMessageAsync(message.NegotiationData);
						Assert.Equal(message.Value, Utilities.ReadMessage(stream));

						stream.Position = 0;
						Assert.Equal(message.NegotiationData ?? empty, await initSocket.ReadNegotiationDataAsync());

						initSocket.Retry(protocol, initConfig);
						await initSocket.IgnoreHandshakeMessageAsync();
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
							Assert.Equal(message.NegotiationData ?? empty, await reader.ReadNegotiationDataAsync());
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

					writer.Dispose();
					reader.Dispose();
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
