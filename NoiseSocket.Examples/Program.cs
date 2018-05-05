using System.Threading.Tasks;

namespace Noise.Examples
{
	public class Program
	{
		public static void Main(string[] args)
		{
			Run().GetAwaiter().GetResult();
		}

		private static async Task Run()
		{
			await AcceptExample.Run();
			await SwitchExample.Run();
			await RetryExample.Run();
		}
	}
}
