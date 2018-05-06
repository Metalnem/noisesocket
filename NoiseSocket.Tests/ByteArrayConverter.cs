using System;
using Newtonsoft.Json;

namespace Noise.Tests
{
	public class ByteArrayConverter : JsonConverter<byte[]>
	{
		public override byte[] ReadJson(
			JsonReader reader,
			Type objectType,
			byte[] existingValue,
			bool hasExistingValue,
			JsonSerializer serializer)
		{
			return Hex.Decode((string)reader.Value);
		}

		public override void WriteJson(JsonWriter writer, byte[] value, JsonSerializer serializer)
		{
			writer.WriteValue(Hex.Encode(value));
		}
	}
}
