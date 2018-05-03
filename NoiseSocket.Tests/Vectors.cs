using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Noise.Tests
{
	internal static class Vectors
	{
		private const string Prologue = "4a6f686e2047616c74";
		private const string InitStatic = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
		private const string InitStaticPublic = "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a";
		private const string InitEphemeral = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
		private const string RespStatic = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
		private const string RespStaticPublic = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
		private const string RespEphemeral = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

		public static IEnumerable<Vector> Generate()
		{
			var flags = BindingFlags.Instance | BindingFlags.NonPublic;
			var protocolName = typeof(Protocol).GetProperty("Name", flags);
			var localStaticRequired = typeof(HandshakePattern).GetMethod("LocalStaticRequired", flags);
			var remoteStaticRequired = typeof(HandshakePattern).GetMethod("RemoteStaticRequired", flags);

			var trueArray = new object[] { true };
			var falseArray = new object[] { false };

			foreach (var protocol in Protocols)
			{
				bool hasInitStatic = (bool)localStaticRequired.Invoke(protocol.HandshakePattern, trueArray);
				bool hasInitRemoteStatic = (bool)remoteStaticRequired.Invoke(protocol.HandshakePattern, trueArray);

				bool hasRespStatic = (bool)localStaticRequired.Invoke(protocol.HandshakePattern, falseArray);
				bool hasRespRemoteStatic = (bool)remoteStaticRequired.Invoke(protocol.HandshakePattern, falseArray);

				var vector = new Vector
				{
					ProtocolName = Hex.Encode((byte[])protocolName.GetValue(protocol)),
					InitPrologue = Prologue,
					InitStatic = hasInitStatic ? InitStatic : null,
					InitEphemeral = InitEphemeral,
					InitRemoteStatic = hasInitRemoteStatic ? RespStaticPublic : null,
					RespPrologue = Prologue,
					RespStatic = hasRespStatic ? RespStatic : null,
					RespEphemeral = RespEphemeral,
					RespRemoteStatic = hasRespRemoteStatic ? InitStaticPublic : null
				};

				yield return vector;
			}
		}

		private static IEnumerable<HandshakePattern> Patterns
		{
			get
			{
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

		private static IEnumerable<Protocol> Protocols
		{
			get
			{
				return from pattern in Patterns
					   from cipher in Ciphers
					   from hash in Hashes
					   select new Protocol(pattern, cipher, hash);
			}
		}
	}
}
