namespace Noise.Examples
{
	public class Program
	{
		public static void Main(string[] args)
		{
			AcceptExample.Run().GetAwaiter().GetResult();
			SwitchExample.Run().GetAwaiter().GetResult();
		}
	}
}
