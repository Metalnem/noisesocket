namespace Noise.Tests
{
	internal sealed class TestConfig
	{
		public Protocol Protocol;
		public byte[] NameBytes;
		public string NameString;
		public bool InitStaticRequired;
		public bool InitRemoteStaticRequired;
		public bool RespStaticRequired;
		public bool RespRemoteStaticRequired;
		public int PaddedLength;
	}
}
