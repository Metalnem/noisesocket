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
		private const int PaddedLength = 117;

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
			using (var client = new TcpClient())
			{
				await client.ConnectAsync(IPAddress.Loopback, Port);

				using (var keyPair = KeyPair.Generate())
				{
					var config = new ProtocolConfig(initiator: true, s: keyPair.PrivateKey);

					using (var stream = client.GetStream())
					using (var noise = new NoiseSocket(protocol, config, stream))
					{
						await noise.WriteHandshakeMessageAsync(negotiationData, paddedLength: PaddedLength);
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);

						var request = Encoding.UTF8.GetBytes("I'm cooking MC's like a pound of bacon");
						await noise.WriteMessageAsync(request, PaddedLength);

						var response = await noise.ReadMessageAsync();
						Console.WriteLine(Encoding.UTF8.GetString(response));
					}
				}
			}
		}

		private static async Task Server()
		{
			var listener = new TcpListener(IPAddress.Loopback, Port);
			listener.Start();

			try
			{
				using (var client = await listener.AcceptTcpClientAsync())
				using (var keyPair = KeyPair.Generate())
				{
					var config = new ProtocolConfig(initiator: false, s: keyPair.PrivateKey);

					using (var stream = client.GetStream())
					using (var noise = new NoiseSocket(protocol, config, stream))
					{
						await noise.ReadNegotiationDataAsync();
						noise.Accept(protocol, config);

						await noise.ReadHandshakeMessageAsync();
						await noise.WriteHandshakeMessageAsync(paddedLength: PaddedLength);
						await noise.ReadNegotiationDataAsync();
						await noise.ReadHandshakeMessageAsync();

						var request = await noise.ReadMessageAsync();
						await noise.WriteMessageAsync(request, PaddedLength);
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
