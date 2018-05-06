using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Noise.Tests
{
	internal static class Vectors
	{
		private const string PrologueHex = "4a6f686e2047616c74";
		private static readonly byte[] PrologueRaw = Hex.Decode(PrologueHex);

		private const string InitStaticHex = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
		private static readonly byte[] InitStaticRaw = Hex.Decode(InitStaticHex);

		private const string InitStaticPublicHex = "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a";
		private static readonly byte[] InitStaticPublicRaw = Hex.Decode(InitStaticPublicHex);

		private const string InitEphemeralHex = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
		private static readonly byte[] InitEphemeralRaw = Hex.Decode(InitEphemeralHex);

		private const string RespStaticHex = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
		private static readonly byte[] RespStaticRaw = Hex.Decode(RespStaticHex);

		private const string RespStaticPublicHex = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
		private static readonly byte[] RespStaticPublicRaw = Hex.Decode(RespStaticPublicHex);

		private const string RespEphemeralHex = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
		private static readonly byte[] RespEphemeralRaw = Hex.Decode(RespEphemeralHex);

		private const string NegotiationDataHex = "4e6f697365536f636b6574";
		private static readonly byte[] NegotiationDataRaw = Hex.Decode(NegotiationDataHex);

		private static readonly List<string> messagesHex = new List<string>
		{
			"4c756477696720766f6e204d69736573",
			"4d757272617920526f746862617264",
			"462e20412e20486179656b",
			"4361726c204d656e676572",
			"4a65616e2d426170746973746520536179",
			"457567656e2042f6686d20766f6e2042617765726b"
		};

		private static readonly List<byte[]> messagesRaw = messagesHex.Select(Hex.Decode).ToList();

		public static async Task<IEnumerable<Vector>> Generate()
		{
			var vectors = new List<Vector>();

			using (var stream = new MemoryStream())
			{
				foreach (var config in GetTestConfigs())
				{
					var initConfig = new ProtocolConfig(
						initiator: true,
						prologue: PrologueRaw,
						s: config.InitStaticRequired ? InitStaticRaw : null,
						rs: config.InitRemoteStaticRequired ? RespStaticPublicRaw : null
					);

					var respConfig = new ProtocolConfig(
						initiator: false,
						prologue: PrologueRaw,
						s: config.RespStaticRequired ? RespStaticRaw : null,
						rs: config.RespRemoteStaticRequired ? InitStaticPublicRaw : null
					);

					var initSocket = NoiseSocket.CreateClient(config.Protocol, initConfig, stream, true);
					var respSocket = NoiseSocket.CreateServer(stream, true);

					initSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, InitEphemeralRaw.ToArray()));
					respSocket.SetInitializer(handshakeState => Utilities.SetDh(handshakeState, RespEphemeralRaw.ToArray()));

					var messages = new List<Message>();
					var paddedLength = (ushort)config.PaddedLength;

					bool hasData = true;
					bool isOneWay = config.Protocol.HandshakePattern.Patterns.Count() == 1;

					for (int i = 0; i < messagesHex.Count; ++i)
					{
						stream.Position = 0;

						if (initSocket.HandshakeHash.IsEmpty)
						{
							var negotiationData = hasData ? NegotiationDataRaw : null;
							var isNextMessageEncrypted = initSocket.IsNextMessageEncrypted;
							await initSocket.WriteHandshakeMessageAsync(negotiationData, messagesRaw[i], paddedLength);

							var message = new Message
							{
								NegotiationData = hasData ? NegotiationDataHex : null,
								MessageBody = messagesHex[i],
								PaddedLength = isNextMessageEncrypted ? paddedLength : 0,
								Value = Utilities.ReadMessageHex(stream)
							};

							messages.Add(message);
							hasData = false;

							stream.Position = 0;
							await respSocket.ReadNegotiationDataAsync();

							if (i == 0)
							{
								respSocket.Accept(config.Protocol, respConfig);
							}

							await respSocket.ReadHandshakeMessageAsync();

							if (isOneWay)
							{
								stream.Position = 0;
								await respSocket.WriteEmptyHandshakeMessageAsync();
								messages.Add(new Message { Value = Utilities.ReadMessageHex(stream) });
							}
						}
						else
						{
							await initSocket.WriteMessageAsync(messagesRaw[i], paddedLength);

							var message = new Message
							{
								MessageBody = messagesHex[i],
								PaddedLength = paddedLength,
								Value = Utilities.ReadMessageHex(stream)
							};

							messages.Add(message);
						}

						if (!isOneWay)
						{
							var temp = initSocket;
							initSocket = respSocket;
							respSocket = temp;
						}
					}

					var vector = new Vector
					{
						ProtocolName = config.NameString,
						InitPrologue = PrologueHex,
						InitStatic = config.InitStaticRequired ? InitStaticHex : null,
						InitEphemeral = InitEphemeralHex,
						InitRemoteStatic = config.InitRemoteStaticRequired ? RespStaticPublicHex : null,
						RespPrologue = PrologueHex,
						RespStatic = config.RespStaticRequired ? RespStaticHex : null,
						RespEphemeral = RespEphemeralHex,
						RespRemoteStatic = config.RespRemoteStaticRequired ? InitStaticPublicHex : null,
						HandshakeHash = Hex.Encode(initSocket.HandshakeHash.ToArray()),
						Messages = messages
					};

					initSocket.Dispose();
					respSocket.Dispose();

					vectors.Add(vector);
				}
			}

			return vectors;
		}

		private static IEnumerable<HandshakePattern> Patterns
		{
			get
			{
				yield return HandshakePattern.N;
				yield return HandshakePattern.K;
				yield return HandshakePattern.X;
				yield return HandshakePattern.NN;
				yield return HandshakePattern.NK;
				yield return HandshakePattern.NX;
				yield return HandshakePattern.XN;
				yield return HandshakePattern.XK;
				yield return HandshakePattern.XX;
				yield return HandshakePattern.KN;
				yield return HandshakePattern.KK;
				yield return HandshakePattern.KX;
				yield return HandshakePattern.IN;
				yield return HandshakePattern.IK;
				yield return HandshakePattern.IX;
			}
		}

		private static IEnumerable<CipherFunction> Ciphers
		{
			get
			{
				yield return CipherFunction.AesGcm;
				yield return CipherFunction.ChaChaPoly;
			}
		}

		private static IEnumerable<HashFunction> Hashes
		{
			get
			{
				yield return HashFunction.Sha256;
				yield return HashFunction.Sha512;
				yield return HashFunction.Blake2s;
				yield return HashFunction.Blake2b;
			}
		}

		private static IEnumerable<int> PaddedLengths
		{
			get
			{
				yield return 0;
				yield return 32;
			}
		}

		private static IEnumerable<TestConfig> GetTestConfigs()
		{
			foreach (var pattern in Patterns)
			{
				bool initStaticRequired = pattern.LocalStaticRequired(true);
				bool initRemoteStaticRequired = pattern.RemoteStaticRequired(true);

				bool respStaticRequired = pattern.LocalStaticRequired(false);
				bool respRemoteStaticRequired = pattern.RemoteStaticRequired(false);

				foreach (var cipher in Ciphers)
				{
					foreach (var hash in Hashes)
					{
						var protocol = new Protocol(pattern, cipher, hash);
						var name = Encoding.ASCII.GetString(protocol.Name);

						foreach (var paddedLength in PaddedLengths)
						{
							yield return new TestConfig
							{
								Protocol = protocol,
								NameBytes = protocol.Name,
								NameString = name,
								InitStaticRequired = initStaticRequired,
								InitRemoteStaticRequired = initRemoteStaticRequired,
								RespStaticRequired = respStaticRequired,
								RespRemoteStaticRequired = respRemoteStaticRequired,
								PaddedLength = paddedLength
							};
						}
					}
				}
			}
		}
	}
}
