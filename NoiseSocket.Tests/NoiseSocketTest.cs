using System;
using System.IO;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Noise.Tests
{
	public class NoiseSocketTest
	{
		[Fact]
		public void TestVectors()
		{
			var s = File.ReadAllText("Vectors/noisesocket.json");
			var json = JObject.Parse(s);

			using (var stream = new MemoryStream())
			{
				foreach (var vector in json["vectors"])
				{
					var protocolName = GetString(vector, "protocol_name");
					var initPrologue = GetBytes(vector, "init_prologue");
					var initStatic = GetBytes(vector, "init_static");
					var initEphemeral = GetBytes(vector, "init_ephemeral");
					var initRemoteStatic = GetBytes(vector, "init_remote_static");
					var respPrologue = GetBytes(vector, "resp_prologue");
					var respStatic = GetBytes(vector, "resp_static");
					var respEphemeral = GetBytes(vector, "resp_ephemeral");
					var respRemoteStatic = GetBytes(vector, "resp_remote_static");
					var handshakeHash = GetBytes(vector, "handshake_hash");

					var initConfig = new ProtocolConfig(true, initPrologue, initStatic, initRemoteStatic);
					var respConfig = new ProtocolConfig(false, respPrologue, respStatic, respRemoteStatic);

					var protocol = Protocol.Parse(protocolName.AsSpan());

					var initSocket = NoiseSocket.CreateClient(protocol, initConfig, stream, true);
					var respSocket = NoiseSocket.CreateServer(stream, true);

					initSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, initEphemeral));
					respSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, respEphemeral));

					bool accepted = false;

					foreach (var message in vector["messages"])
					{
						stream.Position = 0;

						var negotiationData = GetBytes(message, "negotiation_data");
						var messageBody = GetBytes(message, "message_body");
						var paddedLength = (ushort?)message["padded_length"] ?? 0;
						var value = GetBytes(message, "message");

						if (initSocket.HandshakeHash.IsEmpty)
						{
							initSocket.WriteHandshakeMessageAsync(negotiationData, messageBody, paddedLength).GetAwaiter().GetResult();
							var initMessage = Utilities.ReadMessageRaw(stream);
							Assert.Equal(value, initMessage);

							stream.Position = 0;
							var respNegotiationData = respSocket.ReadNegotiationDataAsync().GetAwaiter().GetResult();
							Assert.Equal(negotiationData, respNegotiationData);

							if (!accepted)
							{
								respSocket.Accept(protocol, respConfig);
								accepted = true;
							}

							var respMessageBody = respSocket.ReadHandshakeMessageAsync().GetAwaiter().GetResult();
							Assert.Equal(messageBody, respMessageBody);
						}
						else
						{
							initSocket.WriteMessageAsync(messageBody, paddedLength).GetAwaiter().GetResult();
							var initMessage = Utilities.ReadMessageRaw(stream);
							Assert.Equal(value, initMessage);

							stream.Position = 0;
							var respMessageBody = respSocket.ReadMessageAsync().GetAwaiter().GetResult();
							Assert.Equal(messageBody, respMessageBody);
						}

						var temp = initSocket;
						initSocket = respSocket;
						respSocket = temp;
					}

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
