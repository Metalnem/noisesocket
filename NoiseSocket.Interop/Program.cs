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
		private const int PaddedLength = 100;

		private static readonly Protocol protocol = Protocol.Parse("Noise_XX_25519_AESGCM_BLAKE2b".AsSpan());
		private static readonly byte[] negotiationData = new byte[] { 0, 1, 1, 2, 2, 9 };

		public static void Main(string[] args)
		{
			Run().GetAwaiter().GetResult();
		}

		private static async Task Run()
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
						await noise.WriteHandshakeMessageAsync(negotiationData: negotiationData, paddedLength: PaddedLength);

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
	}
}
