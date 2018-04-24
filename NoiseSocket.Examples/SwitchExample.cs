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
		private const int PaddedLength = 2048;

		private static readonly Protocol protocol = Protocol.Parse("Noise_XX_25519_AESGCM_BLAKE2b".AsSpan());
		private static readonly byte[] negotiationData = new byte[] { 0, 1, 1, 2, 2, 9 };

		public static Task Run()
		{
			var client = Task.Run(Client);
			var server = Task.Run(Server);

			return Task.WhenAll(client, server);
		}

		private static async Task Client()
		{
			using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
			{
				await socket.ConnectAsync(IPAddress.Loopback, Port);

				var initial = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256".AsSpan());
				var config = new ProtocolConfig(initiator: true);

				using (var keyPair = KeyPair.Generate())
				using (var stream = new NetworkStream(socket))
				using (var noise = new NoiseSocket(initial, config, stream))
				{
					await noise.WriteHandshakeMessageAsync(negotiationData, paddedLength: PaddedLength);
					await noise.ReadNegotiationDataAsync();

					config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);
					noise.Switch(protocol, config);

					await noise.ReadHandshakeMessageAsync();
					await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);
					await noise.ReadNegotiationDataAsync();
					await noise.ReadHandshakeMessageAsync();

					var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
					await noise.WriteMessageAsync(request, PaddedLength);

					var response = await noise.ReadMessageAsync();
					Console.WriteLine(Encoding.UTF8.GetString(response));
				}
			}
		}

		private static async Task Server()
		{
			using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
			{
				socket.Bind(new IPEndPoint(IPAddress.Loopback, Port));
				socket.Listen((int)SocketOptionName.MaxConnections);

				var initial = Protocol.Parse("Noise_IN_25519_AESGCM_BLAKE2s".AsSpan());
				var config = new ProtocolConfig(initiator: false);

				using (var client = await socket.AcceptAsync())
				using (var keyPair = KeyPair.Generate())
				using (var stream = new NetworkStream(client))
				using (var noise = new NoiseSocket(initial, config, stream))
				{
					await noise.ReadNegotiationDataAsync();

					config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);
					noise.Switch(protocol, config);

					await noise.IgnoreHandshakeMessageAsync();
					await noise.WriteHandshakeMessageAsync(negotiationData, paddedLength: PaddedLength);
					await noise.ReadNegotiationDataAsync();
					await noise.ReadHandshakeMessageAsync();
					await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);

					var request = await noise.ReadMessageAsync();
					await noise.WriteMessageAsync(request, PaddedLength);
				}
			}
		}
	}
}
