using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Noise.Examples
{
	public class Program
	{
		private const int Port = 10101;
		private const int Padding = 117;

		private static readonly Protocol protocol = Protocol.Parse("Noise_XX_25519_AESGCM_BLAKE2b".AsSpan());
		private static readonly byte[] negotiationData = new byte[] { 0, 1, 1, 2, 2, 9 };

		public static void Main(string[] args)
		{
			var client = Task.Run(Client);
			var server = Task.Run(Server);

			Task.WhenAll(client, server).GetAwaiter().GetResult();
		}

		private static async Task Client()
		{
			using (var client = new TcpClient())
			{
				await client.ConnectAsync(IPAddress.Loopback, Port);

				using (var stream = client.GetStream())
				using (var keyPair = KeyPair.Generate())
				{
					var config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);

					using (var socket = new NoiseSocket(protocol, config, stream))
					{
						await socket.WriteHandshakeMessageAsync(negotiationData);
						await socket.ReadNegotiationDataAsync();
						await socket.ReadHandshakeMessageAsync();
						await socket.WriteHandshakeMessageAsync(null);

						var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
						await socket.WriteMessageAsync(request, Padding);

						var response = await socket.ReadMessageAsync();
						Console.WriteLine(Encoding.UTF8.GetString(response));
					}
				}
			}
		}

		private static async Task Server()
		{
			var listener = new TcpListener(IPAddress.Loopback, Port);
			listener.Start();

			using (var client = await listener.AcceptTcpClientAsync())
			using (var stream = client.GetStream())
			using (var keyPair = KeyPair.Generate())
			{
				var config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);

				using (var socket = new NoiseSocket(protocol, config, stream))
				{
					await socket.ReadNegotiationDataAsync();
					await socket.ReadHandshakeMessageAsync();
					await socket.WriteHandshakeMessageAsync(null);
					await socket.ReadNegotiationDataAsync();
					await socket.ReadHandshakeMessageAsync();

					var request = await socket.ReadMessageAsync();
					await socket.WriteMessageAsync(request, Padding);
				}
			}

			listener.Stop();
		}
	}
}
