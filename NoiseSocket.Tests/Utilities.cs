using System;
using System.IO;
using System.Reflection;

namespace Noise.Tests
{
	internal static class Utilities
	{
		public static void SetDh(HandshakeState state, byte[] ephemeral)
		{
			var flags = BindingFlags.Instance | BindingFlags.NonPublic;
			var setDh = state.GetType().GetMethod("SetDh", flags);

			setDh.Invoke(state, new object[] { new FixedKeyDh(ephemeral) });
		}

		public static byte[] ReadMessage(MemoryStream stream)
		{
			byte[] message = new byte[stream.Position];
			Array.Copy(stream.GetBuffer(), 0, message, 0, message.Length);

			return message;
		}

		public static void Swap<T>(ref T x, ref T y)
		{
			var temp = x;
			x = y;
			y = temp;
		}
	}
}
