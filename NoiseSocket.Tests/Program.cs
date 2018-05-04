using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;

namespace Noise.Tests
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			var dir = Directory.CreateDirectory("Vectors");
			var path = Path.Combine(dir.Name, "noisesocket.json");

			using (var file = File.Create(path))
			using (var writer = new StreamWriter(file))
			using (var json = new JsonTextWriter(writer) { Formatting = Formatting.Indented, Indentation = 0 })
			{
				var serializer = new JsonSerializer { NullValueHandling = NullValueHandling.Ignore };

				var vectors = new Dictionary<string, object>
				{
					["vectors"] = Vectors.Generate()
				};

				serializer.Serialize(json, vectors);
			}
		}
	}
}
