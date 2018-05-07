using System;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;

namespace Noise.Examples
{
	public static class RetryExample
	{
		private const string ServerName = ".";
		private const string PipeName = "NoiseSocket";

		// The agreed protocol between the client and the server. In the real world it would
		// be somehow encoded in the negotiation data in the initial handshake message.
		private static readonly Protocol protocol = Protocol.Parse("Noise_XX_25519_AESGCM_BLAKE2b".AsSpan());

		public static Task Run()
		{
			var client = Task.Run(Client);
			var server = Task.Run(Server);

			return Task.WhenAll(client, server);
		}

		private static async Task Client()
		{
			// Connect to the server using the named pipe.
			using (var client = new NamedPipeClientStream(ServerName, PipeName, PipeDirection.InOut))
			{
				await client.ConnectAsync();

				// Select the initial Noise protocol and configuration.
				var initial = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256".AsSpan());
				var config = new ProtocolConfig(initiator: true);

				using (var noise = new NoiseSocket(initial, config, client))
				{
					// Send the initial handshake message to the server. In the real world the
					// negotiation data would contain the initial protocol, supported protocols
					// for the switch and retry cases, and maybe some other negotiation options.
					await noise.WriteHandshakeMessageAsync(negotiationData: null);

					// Receive the negotiation data from the server. In this example we will
					// assume that the server decided to retry with Noise_XX_25519_AESGCM_BLAKE2b.
					await noise.ReadNegotiationDataAsync();

					// New protocol requires static key, so it's generated here.
					using (var keyPair = KeyPair.Generate())
					{
						// The client again plays the role of the initiator.
						config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);

						// Retry with a protocol different from the initial one.
						noise.Retry(protocol, config);

						// Ignore the empty handshake message.
						await noise.IgnoreHandshakeMessageAsync();

						// Finish the handshake using the new protocol.
						await noise.WriteHandshakeMessageAsync();
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync();

						// Send the transport message to the server.
						var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
						await noise.WriteMessageAsync(request);

						// Receive the transport message from the
						// server and print it to the standard output.
						var response = await noise.ReadMessageAsync();
						Console.WriteLine(Encoding.UTF8.GetString(response));
					}
				}
			}
		}

		private static async Task Server()
		{
			// Create the named pipe and wait for the client to connect to it.
			using (var server = new NamedPipeServerStream(PipeName, PipeDirection.InOut))
			{
				await server.WaitForConnectionAsync();

				// Initialize the NoiseSocket.
				using (var noise = new NoiseSocket(server))
				{
					// Receive the negotiation data from the client. In the real world the
					// negotiation data would contain the initial protocol, supported protocols
					// for the switch and retry cases, and maybe some other negotiation options.
					await noise.ReadNegotiationDataAsync();

					// Read the handshake message from the client, but without decrypting it.
					await noise.IgnoreHandshakeMessageAsync();

					// New protocol requires static key, so we generate it here.
					using (var keyPair = KeyPair.Generate())
					{
						// The server decides to retry with a new protocol.
						// It again plays the role of the responder.
						var config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);
						noise.Retry(protocol, config);

						// Request a retry from the client. In the real world the negotiation data
						// would encode the details about the server's desicion to make a retry request.
						await noise.WriteEmptyHandshakeMessageAsync(negotiationData: null);

						// Receive the negotiation data from the client. The client will
						// usually just confirm the server's choice of the retry protocol.
						await noise.ReadNegotiationDataAsync();

						// Finish the handshake using the new protocol.
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync();
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();

						// Receive the transport message from the client.
						var request = await noise.ReadMessageAsync();

						// Echo the message back to the client.
						await noise.WriteMessageAsync(request);
					}
				}
			}
		}
	}
}
