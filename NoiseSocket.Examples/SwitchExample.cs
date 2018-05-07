using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Noise.Examples
{
	public static class SwitchExample
	{
		private const int Port = 56473;

		// Pad all the messages to 2048 bytes to hide the plaintext length.
		private const int PaddedLength = 2048;

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
			// Connect to the server using the TCP socket.
			using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
			{
				await socket.ConnectAsync(IPAddress.Loopback, Port);

				// Select the initial Noise protocol and configuration.
				var initial = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256".AsSpan());
				var config = new ProtocolConfig(initiator: true);

				// Initialize the NoiseSocket with the network stream.
				using (var stream = new NetworkStream(socket))
				using (var noise = new NoiseSocket(initial, config, stream))
				{
					// Send the initial handshake message to the server. In the real world the
					// negotiation data would contain the initial protocol, supported protocols
					// for the switch and retry cases, and maybe some other negotiation options.
					await noise.WriteHandshakeMessageAsync(negotiationData: null, paddedLength: PaddedLength);

					// Receive the negotiation data from the server. In this example we will
					// assume that the server decided to switch to Noise_XX_25519_AESGCM_BLAKE2b.
					await noise.ReadNegotiationDataAsync();

					// New protocol requires static key, so it's generated here.
					using (var keyPair = KeyPair.Generate())
					{
						// The client now plays the role of the responder.
						config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);

						// Switch to a protocol different from the initial one.
						noise.Switch(protocol, config);

						// Finish the handshake using the new protocol.
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();

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
			// Listen for incoming TCP connections.
			using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
			{
				socket.Bind(new IPEndPoint(IPAddress.Loopback, Port));
				socket.Listen((int)SocketOptionName.MaxConnections);

				// Accept the connection and initialize the NoiseSocket with its network stream.
				using (var client = await socket.AcceptAsync())
				using (var stream = new NetworkStream(client))
				using (var noise = new NoiseSocket(stream))
				{
					// Receive the negotiation data from the client. In the real world the
					// negotiation data would contain the initial protocol, supported protocols
					// for the switch and retry cases, and maybe some other negotiation options.
					await noise.ReadNegotiationDataAsync();

					// New protocol requires static key, so we generate it here.
					using (var keyPair = KeyPair.Generate())
					{
						// The server decides to switch to a new protocol.
						// It now plays the role of the initiator.
						var config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);
						noise.Switch(protocol, config);

						// Read the handshake message from the client, but without decrypting it.
						await noise.IgnoreHandshakeMessageAsync();

						// Send the first handshake message using the new protocol. In the
						// real world the negotiation data would encode the details about
						// the server's desicion to switch protocol.
						await noise.WriteHandshakeMessageAsync(negotiationData: null, paddedLength: PaddedLength);

						// Finish the handshake using the new protocol.
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);

						// Receive the transport message from the client.
						var request = await noise.ReadMessageAsync();

						// Echo the message back to the client.
						await noise.WriteMessageAsync(request, PaddedLength);
					}
				}
			}
		}
	}
}
