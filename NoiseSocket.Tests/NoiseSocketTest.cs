using System;
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

					var protocolName = GetString(initialConfig, "protocol_name");
					var initPrologue = GetBytes(vector, "init_prologue");
					var initStatic = GetBytes(initialConfig, "init_static");
					var initEphemeral = GetBytes(initialConfig, "init_ephemeral");
					var initRemoteStatic = GetBytes(initialConfig, "init_remote_static");
					var respPrologue = GetBytes(vector, "resp_prologue");
					var respStatic = GetBytes(initialConfig, "resp_static");
					var respEphemeral = GetBytes(initialConfig, "resp_ephemeral");
					var respRemoteStatic = GetBytes(initialConfig, "resp_remote_static");
					var handshakeHash = GetBytes(vector, "handshake_hash");

					var initConfig = new ProtocolConfig(true, initPrologue, initStatic, initRemoteStatic);
					var respConfig = new ProtocolConfig(false, respPrologue, respStatic, respRemoteStatic);

					var protocol = Protocol.Parse(protocolName.AsSpan());
					var accepted = false;

					var initSocket = NoiseSocket.CreateClient(protocol, initConfig, stream, true);
					var respSocket = NoiseSocket.CreateServer(stream, true);

					initSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, initEphemeral));
					respSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, respEphemeral));

					foreach (var message in vector["messages"])
					{
						stream.Position = 0;

						var negotiationData = GetBytes(message, "negotiation_data");
						var messageBody = GetBytes(message, "message_body");
						var paddedLength = (ushort?)message["padded_length"] ?? 0;
						var value = GetBytes(message, "message");

						if (initSocket.HandshakeHash.IsEmpty)
						{
							await initSocket.WriteHandshakeMessageAsync(negotiationData, messageBody, paddedLength);
							var initMessage = Utilities.ReadMessageRaw(stream);
							Assert.Equal(value, initMessage);

							stream.Position = 0;
							var respNegotiationData = await respSocket.ReadNegotiationDataAsync();
							Assert.Equal(negotiationData, respNegotiationData);

							if (!accepted)
							{
								respSocket.Accept(protocol, respConfig);
								accepted = true;
							}

							var respMessageBody = await respSocket.ReadHandshakeMessageAsync();
							Assert.Equal(messageBody, respMessageBody);
						}
						else
						{
							await initSocket.WriteMessageAsync(messageBody, paddedLength);
							var initMessage = Utilities.ReadMessageRaw(stream);
							Assert.Equal(value, initMessage);

							stream.Position = 0;
							var respMessageBody = await respSocket.ReadMessageAsync();
							Assert.Equal(messageBody, respMessageBody);
						}

						Utilities.Swap(ref initSocket, ref respSocket);
					}

					Assert.Equal(handshakeHash, initSocket.HandshakeHash.ToArray());
					Assert.Equal(handshakeHash, respSocket.HandshakeHash.ToArray());

					initSocket.Dispose();
					respSocket.Dispose();
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
	}
}
