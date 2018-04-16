using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Noise;

namespace Noise.Examples
{
	public class Program
	{
		private const int Port = 10101;
		private const int Padding = 117;

		private static readonly Protocol protocol = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256".AsReadOnlySpan());
		private static readonly byte[] negotiationData = new byte[] { 0, 1, 1, 1, 3, 9 };

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
				using (var socket = new NoiseSocket(protocol, true, keyPair.PrivateKey))
				{
					await socket.WriteHandshakeMessageAsync(stream, negotiationData, null);
					await socket.ReadNegotiationDataAsync(stream);
					await socket.ReadHandshakeMessageAsync(stream);
					await socket.WriteHandshakeMessageAsync(stream, null, null);

					var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
					await socket.WriteMessageAsync(stream, request, Padding);

					var response = await socket.ReadMessageAsync(stream);
					Console.WriteLine(Encoding.UTF8.GetString(response));
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
			using (var socket = new NoiseSocket(protocol, false, keyPair.PrivateKey))
			{
				await socket.ReadNegotiationDataAsync(stream);
				await socket.ReadHandshakeMessageAsync(stream);
				await socket.WriteHandshakeMessageAsync(stream, null, null);
				await socket.ReadNegotiationDataAsync(stream);
				await socket.ReadHandshakeMessageAsync(stream);

				var request = await socket.ReadMessageAsync(stream);
				await socket.WriteMessageAsync(stream, request, Padding);
			}

			listener.Stop();
		}
	}
}
