using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Noise
{
	/// <summary>
	/// NoiseSocket provides an encoding layer for the Noise Protocol
	/// Framework. NoiseSocket can encode Noise messages and associated
	/// negotiation data into a form suitable for transmission over
	/// reliable, stream-based protocols such as TCP.
	/// </summary>
	public sealed class NoiseSocket : IDisposable
	{
		private const int LenFieldSize = 2;
		private const int TagSize = 16;
		private const int MaxSavedMessagesCount = 3;

		private static readonly byte[] empty = new byte[0];
		private static readonly byte[] noiseSocketInit1 = Encoding.UTF8.GetBytes("NoiseSocketInit1");
		private static readonly byte[] noiseSocketInit2 = Encoding.UTF8.GetBytes("NoiseSocketInit2");
		private static readonly byte[] noiseSocketInit3 = Encoding.UTF8.GetBytes("NoiseSocketInit3");

		private readonly bool client;
		private Protocol protocol;
		private ProtocolConfig config;
		private readonly Stream stream;
		private readonly bool leaveOpen;

		private HandshakeState handshakeState;
		private Transport transport;

		private byte[] noiseSocketInit = noiseSocketInit1;
		private List<SavedMessage> savedMessages = new List<SavedMessage>();

		private bool isNextMessageEncrypted;
		private bool allowReinitialization;
		private bool disposed;

		private NoiseSocket(bool client, Protocol protocol, ProtocolConfig config, Stream stream, bool leaveOpen = false)
		{
			this.client = client;
			this.protocol = protocol;
			this.config = config;
			this.stream = stream;
			this.leaveOpen = leaveOpen;

			isNextMessageEncrypted = protocol != null && IsInitialMessageEncrypted(protocol);
			allowReinitialization = true;
		}

		/// <summary>
		/// Initializes a new client instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="config">
		/// A set of parameters used to instantiate an initial <see cref="HandshakeState"/>.
		/// </param>
		/// <param name="stream">The stream for reading and writing encoded protocol messages.</param>
		/// <param name="leaveOpen">
		/// True to leave the stream open after the
		/// <see cref="NoiseSocket"/> object is disposed, false otherwise.
		/// </param>
		/// <returns>The new <see cref="NoiseSocket"/> client.</returns>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/>,
		/// <paramref name="config"/>, or <paramref name="stream"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the client was initialized as a Noise protocol responder.
		/// </exception>
		public static NoiseSocket CreateClient(Protocol protocol, ProtocolConfig config, Stream stream, bool leaveOpen = false)
		{
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));
			ThrowIfNull(stream, nameof(stream));

			if (!config.Initiator)
			{
				throw new ArgumentException("The client must be initialized as a Noise protocol initiator.");
			}

			return new NoiseSocket(true, protocol, config, stream, leaveOpen);
		}

		/// <summary>
		/// Initializes a new server instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		/// <param name="stream">The stream for reading and writing encoded protocol messages.</param>
		/// <param name="leaveOpen">
		/// True to leave the stream open after the
		/// <see cref="NoiseSocket"/> object is disposed, false otherwise.
		/// </param>
		/// <returns>The new <see cref="NoiseSocket"/> server.</returns>
		/// <exception cref="ArgumentNullException">
		/// Thrown if <paramref name="stream"/> is null.
		/// </exception>
		public static NoiseSocket CreateServer(Stream stream, bool leaveOpen = false)
		{
			ThrowIfNull(stream, nameof(stream));

			return new NoiseSocket(false, null, null, stream, leaveOpen);
		}

		/// <summary>
		/// Initializes the current instance of the <see cref="NoiseSocket"/>
		/// class with an initiator's choice of the Noise protocol.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="config">
		/// A set of parameters used to instantiate a <see cref="HandshakeState"/>.
		/// </param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has already been completed
		/// or if the protocol has already been changed once.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Accept(Protocol protocol, ProtocolConfig config)
		{
			noiseSocketInit = noiseSocketInit1;
			Reinitialize(protocol, config);
		}

		/// <summary>
		/// Reinitializes the current instance of the <see cref="NoiseSocket"/>
		/// class with a new Noise protocol, different from the initial Noise protocol.
		/// The reason for the reinitialization was responder's decision to switch protocol.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="config">
		/// A set of parameters used to instantiate a <see cref="HandshakeState"/>.
		/// </param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has already been completed
		/// or if the protocol has already been changed once.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Switch(Protocol protocol, ProtocolConfig config)
		{
			noiseSocketInit = noiseSocketInit2;
			Reinitialize(protocol, config);
		}

		/// <summary>
		/// Reinitializes the current instance of the <see cref="NoiseSocket"/>
		/// class with a new Noise protocol, different from the initial Noise protocol.
		/// The reason for the reinitialization was responder's retry request.
		/// </summary>
		/// <param name="protocol">A concrete Noise protocol (e.g. Noise_XX_25519_AESGCM_BLAKE2b).</param>
		/// <param name="config">
		/// A set of parameters used to instantiate a <see cref="HandshakeState"/>.
		/// </param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has already been completed
		/// or if the protocol has already been changed once.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Retry(Protocol protocol, ProtocolConfig config)
		{
			noiseSocketInit = noiseSocketInit3;
			Reinitialize(protocol, config);
		}

		private void Reinitialize(Protocol protocol, ProtocolConfig config)
		{
			ThrowIfDisposed();

			if (transport != null)
			{
				throw new InvalidOperationException($"Cannot change protocol after the handshake has been completed.");
			}

			if (!allowReinitialization)
			{
				throw new InvalidOperationException($"Cannot change protocol more than once.");
			}

			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));

			this.protocol = protocol;
			this.config = config;

			if (handshakeState != null)
			{
				handshakeState.Dispose();
				handshakeState = null;
			}

			isNextMessageEncrypted = IsInitialMessageEncrypted(protocol);
			allowReinitialization = false;
		}

		/// <summary>
		/// Asynchronously writes the negotiation data and the handshake message to the input stream.
		/// </summary>
		/// <param name="negotiationData">The negotiation data.</param>
		/// <param name="messageBody">The message body to encrypt.</param>
		/// <param name="paddedLength">
		/// If this message has an encrypted payload and the length of the
		/// <paramref name="messageBody"/> is less than <paramref name="paddedLength"/>,
		/// <paramref name="messageBody"/> is padded to make its
		/// length equal to <paramref name="paddedLength"/>.
		/// </param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the output stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to this method was unexpected in the current state of this object.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if either the negotiation data, or the Noise message was greater
		/// than <see cref="Protocol.MaxMessageLength"/> bytes in length.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public async Task WriteHandshakeMessageAsync(
			Memory<byte> negotiationData = default,
			Memory<byte> messageBody = default,
			ushort paddedLength = default,
			CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (this.transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteHandshakeMessageAsync)} after the handshake has been completed.");
			}

			if (negotiationData.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Negotiation data must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			if (messageBody.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Handshake message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			SaveMessage(MessageType.WriteNegotiationData, negotiationData);
			handshakeState = handshakeState ?? InitializeHandshakeState();

			// negotiation_data_len (2 bytes)
			// negotiation_data
			// noise_message_len (2 bytes)
			// noise_message

			int negotiationLength = LenFieldSize + negotiationData.Length;
			int maxNoiseLength = LenFieldSize + Protocol.MaxMessageLength;

			// Prevent the buffer from going to the LOH (it may be greater than 85000 bytes).
			var pool = ArrayPool<byte>.Shared;
			var buffer = pool.Rent(negotiationLength + maxNoiseLength);

			try
			{
				Memory<byte> plaintext = messageBody;

				if (isNextMessageEncrypted)
				{
					plaintext = new byte[LenFieldSize + Math.Max(messageBody.Length, paddedLength)];
					WritePacket(messageBody.Span, plaintext.Span);
				}

				var ciphertext = buffer.AsMemory(negotiationLength + LenFieldSize);
				var (written, hash, transport) = handshakeState.WriteMessage(plaintext.Span, ciphertext.Span);
				isNextMessageEncrypted = true;

				if (transport != null)
				{
					handshakeState.Dispose();
					handshakeState = null;

					this.transport = transport;
				}

				WritePacket(negotiationData.Span, buffer);
				BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(negotiationLength), (ushort)written);
				SaveMessage(MessageType.WriteNoiseMessage, ciphertext.Slice(0, written));

				int noiseLength = LenFieldSize + written;
				int handshakeLength = negotiationLength + noiseLength;

				await stream.WriteAsync(buffer, 0, handshakeLength, cancellationToken).ConfigureAwait(false);
			}
			finally
			{
				pool.Return(buffer);
			}
		}

		/// <summary>
		/// Asynchronously writes the negotiation data and the empty handshake message to the input stream.
		/// </summary>
		/// <param name="negotiationData">The negotiation data.</param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the output stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to this method was unexpected in the current state of this object.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the negotiation data was greater than
		/// <see cref="Protocol.MaxMessageLength"/> bytes in length.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task WriteEmptyHandshakeMessageAsync(Memory<byte> negotiationData, CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport != null)
			{
				string error = $"Cannot call {nameof(WriteEmptyHandshakeMessageAsync)} after the handshake has been completed.";
				throw new InvalidOperationException(error);
			}

			if (negotiationData.Length > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Negotiation data must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			SaveMessage(MessageType.WriteNegotiationData, negotiationData);
			SaveMessage(MessageType.WriteNoiseMessage, Memory<byte>.Empty, false);

			var message = new byte[LenFieldSize + negotiationData.Length + LenFieldSize];
			WritePacket(negotiationData.Span, message);

			await stream.WriteAsync(message, 0, message.Length, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Asynchronously reads the negotiation data from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the negotiation data.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to this method was unexpected in the current state of this object.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task<byte[]> ReadNegotiationDataAsync(CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadNegotiationDataAsync)} after the handshake has been completed.");
			}

			var negotiationData = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			SaveMessage(MessageType.ReadNegotiationData, negotiationData);

			return negotiationData;
		}

		/// <summary>
		/// Asynchronously reads the handshake message from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the decrypted message body.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to this method was unexpected in the current state of this object.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the decrypted message body length was invalid.
		/// </exception>
		/// <exception cref="System.Security.Cryptography.CryptographicException">
		/// Thrown if the decryption of the message has failed.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public async Task<byte[]> ReadHandshakeMessageAsync(CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (this.transport != null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadHandshakeMessageAsync)} after the handshake has been completed.");
			}

			handshakeState = handshakeState ?? InitializeHandshakeState();

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			SaveMessage(MessageType.ReadNoiseMessage, noiseMessage, false);

			if (noiseMessage.Length == 0)
			{
				return empty;
			}

			var plaintext = new byte[noiseMessage.Length];
			var (read, hash, transport) = handshakeState.ReadMessage(noiseMessage, plaintext);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.transport = transport;
			}

			if (isNextMessageEncrypted)
			{
				return ReadPacket(plaintext.AsSpan(0, read));
			}

			isNextMessageEncrypted = true;
			return plaintext.AsSpan(0, read).ToArray();
		}

		/// <summary>
		/// Asynchronously consumes the handshake message from
		/// the input stream without attempting to decrypt it.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the call to this method was unexpected in the current state of this object.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task IgnoreHandshakeMessageAsync(CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport != null)
			{
				string error = $"Cannot call {nameof(IgnoreHandshakeMessageAsync)} after the handshake has been completed.";
				throw new InvalidOperationException(error);
			}

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			SaveMessage(MessageType.ReadNoiseMessage, noiseMessage, false);
		}

		/// <summary>
		/// Asynchronously writes the transport message to the input stream.
		/// </summary>
		/// <param name="messageBody">The message body to encrypt.</param>
		/// <param name="paddedLength">
		/// If the length of the <paramref name="messageBody"/> is less than
		/// <paramref name="paddedLength"/>, <paramref name="messageBody"/>
		/// is padded to make its length equal to <paramref name="paddedLength"/>.
		/// </param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>A task that represents the asynchronous write operation.</returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the output stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has not yet been completed, or the
		/// responder has attempted to write a message to a one-way stream.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the encrypted payload was greater than
		/// <see cref="Protocol.MaxMessageLength"/> bytes in length.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support writing.</exception>
		public Task WriteMessageAsync(
			Memory<byte> messageBody,
			ushort paddedLength = default,
			CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(WriteMessageAsync)} before the handshake has been completed.");
			}

			int length = Math.Max(messageBody.Length, paddedLength);
			int noiseMessageLength = LenFieldSize + length + TagSize;

			if (noiseMessageLength > Protocol.MaxMessageLength)
			{
				throw new ArgumentException($"Transport message must be less than or equal to {Protocol.MaxMessageLength} bytes in length.");
			}

			var transportMessage = new byte[LenFieldSize + noiseMessageLength];
			var ciphertext = transportMessage.AsMemory(LenFieldSize);

			BinaryPrimitives.WriteUInt16BigEndian(transportMessage.AsSpan(), (ushort)noiseMessageLength);
			WritePacket(messageBody.Span, ciphertext.Span);

			var payload = ciphertext.Slice(0, noiseMessageLength - TagSize);
			var written = transport.WriteMessage(payload.Span, ciphertext.Span);

			return stream.WriteAsync(transportMessage, 0, transportMessage.Length, cancellationToken);
		}

		/// <summary>
		/// Asynchronously reads the transport message from the input stream.
		/// </summary>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		/// <returns>
		/// A task that represents the asynchronous read operation.
		/// The result of the task contains the decrypted message body.
		/// </returns>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if either the current instance, or the input stream has already been disposed.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// Thrown if the handshake has not yet been completed, or the
		/// initiator has attempted to read a message from a one-way stream.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the decrypted message body length was invalid.
		/// </exception>
		/// <exception cref="System.Security.Cryptography.CryptographicException">
		/// Thrown if the decryption of the message has failed.
		/// </exception>
		/// <exception cref="IOException">Thrown if an I/O error occurs.</exception>
		/// <exception cref="NotSupportedException">Thrown if the stream does not support reading.</exception>
		public async Task<byte[]> ReadMessageAsync(CancellationToken cancellationToken = default)
		{
			ThrowIfDisposed();

			if (transport == null)
			{
				throw new InvalidOperationException($"Cannot call {nameof(ReadMessageAsync)} before the handshake has been completed.");
			}

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			var minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			var read = transport.ReadMessage(noiseMessage, noiseMessage);

			return ReadPacket(noiseMessage.AsSpan(0, read));
		}

		private void SaveMessage(MessageType type, Memory<byte> data, bool copy = true)
		{
			if (savedMessages != null)
			{
				// Once we are done with the initial message's negotiation_data,
				// the initial message's noise_message, and the responding
				// message's negotiation_data (that's three messages in total),
				// we no longer have to keep old messages.

				if (savedMessages.Count == MaxSavedMessagesCount)
				{
					savedMessages = null;
				}
				else
				{
					savedMessages.Add(new SavedMessage(type, copy ? data.ToArray() : data));
					ThrowIfPrologueInvalid(false);
				}
			}
		}

		private HandshakeState InitializeHandshakeState()
		{
			Debug.Assert(savedMessages != null);

			if (protocol == null)
			{
				string error = $"Cannot perform the handshake before calling either {nameof(Accept)}, {nameof(Switch)}, or {nameof(Retry)}.";
				throw new InvalidOperationException(error);
			}

			ThrowIfPrologueInvalid(true);

			var prologue = this.config.Prologue.AsSpan();
			var length = noiseSocketInit.Length + savedMessages.Sum(message => LenFieldSize + message.Data.Length) + prologue.Length;
			var buffer = new byte[length];

			noiseSocketInit.AsSpan().CopyTo(buffer);
			var next = buffer.AsSpan(noiseSocketInit.Length);

			foreach (var message in savedMessages)
			{
				WritePacket(message.Data.Span, next);
				next = next.Slice(LenFieldSize + message.Data.Length);
			}

			prologue.CopyTo(next);

			if (!allowReinitialization)
			{
				savedMessages = null;
			}

			return protocol.Create(
				config.Initiator,
				buffer,
				config.LocalStatic,
				config.RemoteStatic,
				config.PreSharedKeys
			);
		}

		private bool IsPrologueValid(bool strict)
		{
			Debug.Assert(savedMessages.Count <= MaxSavedMessagesCount);

			if ((noiseSocketInit == noiseSocketInit1 && savedMessages.Count == 1)
				|| (strict && savedMessages.Count == MaxSavedMessagesCount)
				|| (!strict && savedMessages.Count <= MaxSavedMessagesCount))
			{
				var actual = savedMessages.Select(message => message.Type);
				var expected = LongestValidPrologue(client).Take(savedMessages.Count);

				return expected.SequenceEqual(actual);
			}

			return false;
		}

		private static IEnumerable<MessageType> LongestValidPrologue(bool client)
		{
			if (client)
			{
				yield return MessageType.WriteNegotiationData;
				yield return MessageType.WriteNoiseMessage;
				yield return MessageType.ReadNegotiationData;
			}
			else
			{
				yield return MessageType.ReadNegotiationData;
				yield return MessageType.ReadNoiseMessage;
				yield return MessageType.WriteNegotiationData;
			}
		}

		private void ThrowIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(NoiseSocket));
			}
		}

		private void ThrowIfPrologueInvalid(bool strict)
		{
			if (!IsPrologueValid(strict))
			{
				throw new InvalidOperationException("Handshake operations have been performed in wrong order.");
			}
		}

		private static void ThrowIfNull(object value, string name)
		{
			if (value == null)
			{
				throw new ArgumentNullException(name);
			}
		}

		private static void WritePacket(ReadOnlySpan<byte> data, Span<byte> message)
		{
			int length = data.Length;
			Debug.Assert(length < UInt16.MaxValue);
			Debug.Assert(LenFieldSize + length <= message.Length);

			BinaryPrimitives.WriteUInt16BigEndian(message, (ushort)length);
			data.CopyTo(message.Slice(LenFieldSize));
		}

		private static byte[] ReadPacket(ReadOnlySpan<byte> packet)
		{
			Debug.Assert(packet.Length <= UInt16.MaxValue);

			var length = BinaryPrimitives.ReadUInt16BigEndian(packet);
			var data = packet.Slice(LenFieldSize);

			if (length > data.Length)
			{
				throw new ArgumentException("Invalid message body length.");
			}

			return data.Slice(0, length).ToArray();
		}

		private static async Task<byte[]> ReadPacketAsync(Stream stream, CancellationToken cancellationToken = default)
		{
			byte[] length = new byte[LenFieldSize];
			await stream.ReadAsync(length, 0, length.Length, cancellationToken).ConfigureAwait(false);

			byte[] data = new byte[BinaryPrimitives.ReadUInt16BigEndian(length)];
			await stream.ReadAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);

			return data;
		}

		private static bool IsInitialMessageEncrypted(Protocol protocol)
		{
			var psks = PatternModifiers.Psk0 | PatternModifiers.Psk1 | PatternModifiers.Psk2 | PatternModifiers.Psk3;

			if ((protocol.Modifiers & psks) != 0)
			{
				return true;
			}

			foreach (var token in protocol.HandshakePattern.Patterns.First().Tokens)
			{
				switch (token)
				{
					case Token.EE:
					case Token.ES:
					case Token.SE:
					case Token.SS: return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Releases all resources used by the current
		/// instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				if (!leaveOpen)
				{
					stream.Dispose();
				}

				handshakeState?.Dispose();
				transport?.Dispose();

				disposed = true;
			}
		}

		private enum MessageType
		{
			ReadNegotiationData,
			WriteNegotiationData,
			ReadNoiseMessage,
			WriteNoiseMessage
		}

		private struct SavedMessage
		{
			public readonly MessageType Type;
			public readonly Memory<byte> Data;

			public SavedMessage(MessageType type, Memory<byte> data)
			{
				Type = type;
				Data = data;
			}
		}
	}
}
