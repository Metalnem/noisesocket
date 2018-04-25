using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Noise.Examples
{
	public static class AcceptExample
	{
		private const int Port = 19285;

		// Pad all the messages to 117 bytes to hide the plaintext length.
		private const int PaddedLength = 117;

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
			// Open the TCP connection to the server.
			using (var client = new TcpClient())
			{
				await client.ConnectAsync(IPAddress.Loopback, Port);

				// Generate the static key pair.
				using (var keyPair = KeyPair.Generate())
				{
					var config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);

					// Initialize the NoiseSocket with the network stream.
					using (var stream = client.GetStream())
					using (var noise = new NoiseSocket(protocol, config, stream))
					{
						// Send the initial handshake message to the server. In the real world the
						// negotiation data would contain the initial protocol, supported protocols
						// for the switch and retry cases, and maybe some other negotiation options.
						await noise.WriteHandshakeMessageAsync(negotiationData: null, paddedLength: PaddedLength);

						// Receive the negotiation data from the server. In this example we will
						// assume that the server decided to accept the offered protocol.
						await noise.ReadNegotiationDataAsync();

						// Finish the handshake.
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);

						// Send the padded transport message to the server.
						var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
						await noise.WriteMessageAsync(request, PaddedLength);

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
			// Listen for connections from TCP network clients.
			var listener = new TcpListener(IPAddress.Loopback, Port);
			listener.Start();

			try
			{
				// Accept the connection from the TCP client.
				using (var client = await listener.AcceptTcpClientAsync())
				{
					// Generate the static key pair.
					using (var keyPair = KeyPair.Generate())
					{
						var config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);

						// Initialize the NoiseSocket with the network stream.
						using (var stream = client.GetStream())
						using (var noise = new NoiseSocket(protocol, config, stream))
						{
							// Receive the negotiation data from the client. In the real world the
							// negotiation data would contain the initial protocol, supported protocols
							// for the switch and retry cases, and maybe some other negotiation options.
							await noise.ReadNegotiationDataAsync();

							// Accept the offered protocol.
							noise.Accept(protocol, config);

							// Finish the handshake.
							await noise.ReadHandshakeMessageAsync();
							await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);
							await noise.ReadNegotiationDataAsync();
							await noise.ReadHandshakeMessageAsync();

							// Receive the transport message from the client.
							var request = await noise.ReadMessageAsync();

							// Echo the message back to the client.
							await noise.WriteMessageAsync(request, PaddedLength);
						}
					}
				}
			}
			finally
			{
				listener.Stop();
			}
		}
	}
}
