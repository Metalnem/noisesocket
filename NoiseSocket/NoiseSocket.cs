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

		// Once we are sure that we are done with all the messages
		// that are part of the prologue, we no longer have to keep
		// old messages. The maximum number of messages needed for
		// the prologue calculation is five (in the Retry case).
		private const int MaxSavedMessagesCount = 5;

		private static readonly byte[] empty = new byte[0];
		private static readonly byte[] noiseSocketInit1 = Encoding.UTF8.GetBytes("NoiseSocketInit1");
		private static readonly byte[] noiseSocketInit2 = Encoding.UTF8.GetBytes("NoiseSocketInit2");
		private static readonly byte[] noiseSocketInit3 = Encoding.UTF8.GetBytes("NoiseSocketInit3");

		private readonly bool client;
		private Protocol protocol;
		private ProtocolConfig config;
		private State state;
		private readonly Stream stream;
		private readonly bool leaveOpen;

		private HandshakeState handshakeState;
		private Action<HandshakeState> initializer;
		private Transport transport;
		private byte[] handshakeHash;

		private List<Memory<byte>> savedMessages;
		private bool isNextMessageEncrypted;
		private HandshakeOperation lastOperation;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="NoiseSocket"/> class.
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
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/>,
		/// <paramref name="config"/>, or <paramref name="stream"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the selected handshake pattern was a one-way pattern.
		/// </exception>
		public NoiseSocket(Protocol protocol, ProtocolConfig config, Stream stream, bool leaveOpen = false)
		{
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));
			ThrowIfNull(stream, nameof(stream));

			if (protocol.HandshakePattern.Patterns.Count() == 1)
			{
				throw new ArgumentException("One-way patterns are not yet supported.");
			}

			this.client = config.Initiator;
			this.protocol = protocol;
			this.config = config;
			this.stream = stream;
			this.leaveOpen = leaveOpen;

			savedMessages = new List<Memory<byte>>();
			isNextMessageEncrypted = protocol != null && IsInitialMessageEncrypted(protocol);
			lastOperation = config.Initiator ? HandshakeOperation.ReadHandshakeMessage : HandshakeOperation.WriteHandshakeMessage;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="NoiseSocket"/> class.
		/// </summary>
		/// <param name="stream">The stream for reading and writing encoded protocol messages.</param>
		/// <param name="leaveOpen">
		/// True to leave the stream open after the
		/// <see cref="NoiseSocket"/> object is disposed, false otherwise.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// Thrown if <paramref name="stream"/> is null.
		/// </exception>
		public NoiseSocket(Stream stream, bool leaveOpen = false)
		{
			ThrowIfNull(stream, nameof(stream));

			this.stream = stream;
			this.leaveOpen = leaveOpen;

			savedMessages = new List<Memory<byte>>();
			isNextMessageEncrypted = protocol != null && IsInitialMessageEncrypted(protocol);
			lastOperation = HandshakeOperation.WriteHandshakeMessage;
		}

		/// <summary>
		/// A value that hashes all the handshake data that's been sent
		/// and received. It uniquely identifies the Noise session.
		/// It's available only after the handshake has been completed.
		/// </summary>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		public ReadOnlySpan<byte> HandshakeHash
		{
			get
			{
				ThrowIfDisposed();
				return handshakeHash;
			}
		}

		/// <summary>
		/// NoiseSocket.Tests use this value to determine whether
		/// to include the padding in generated test vectors or not,
		/// because the padded length is ignored if the handshake
		/// message is not encrypted.
		/// </summary>
		internal bool IsNextMessageEncrypted => isNextMessageEncrypted;

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
		/// Thrown if the handshake has already been completed,
		/// the protocol has already been changed once, or this
		/// method was called by the client.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the server attempted to accept a new protocol as an initiator
		/// or the selected handshake pattern was a one-way pattern.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Accept(Protocol protocol, ProtocolConfig config)
		{
			ThrowIfDisposed();
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));

			if (client)
			{
				throw new InvalidOperationException($"{nameof(Accept)} can be called only by the server.");
			}

			if (!client && config.Initiator)
			{
				throw new ArgumentException("Server cannot accept a new protocol as an initiator.");
			}

			Reinitialize(protocol, config, State.Accept);
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
		/// or the protocol has already been changed once.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the client attempted to switch to a new protocol as an initiator,
		/// the server attempted to switch to a new protocol as a responder,
		/// or the selected handshake pattern was a one-way pattern.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Switch(Protocol protocol, ProtocolConfig config)
		{
			ThrowIfDisposed();
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));

			if (client && config.Initiator)
			{
				throw new ArgumentException("Client cannot switch to a new protocol as an initiator.");
			}

			if (!client && !config.Initiator)
			{
				throw new ArgumentException("Server cannot switch to a new protocol as a responder.");
			}

			Reinitialize(protocol, config, State.Switch);
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
		/// or the protocol has already been changed once.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="protocol"/> or <paramref name="config"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if the client attempted to retry with a new protocol as a responder,
		/// the server attempted to retry with a new protocol as an initiator,
		/// or the selected handshake pattern was a one-way pattern.
		/// </exception>
		/// <remarks>
		/// This method can also throw all exceptions that <see cref="Protocol.Create(ProtocolConfig)"/>
		/// method can throw. See the <see cref="Protocol"/> class documentation for more details.
		/// </remarks>
		public void Retry(Protocol protocol, ProtocolConfig config)
		{
			ThrowIfDisposed();
			ThrowIfNull(protocol, nameof(protocol));
			ThrowIfNull(config, nameof(config));

			if (client && !config.Initiator)
			{
				throw new ArgumentException("Client cannot retry with a new protocol as a responder.");
			}

			if (!client && config.Initiator)
			{
				throw new ArgumentException("Server cannot retry with a new protocol as an initiator.");
			}

			Reinitialize(protocol, config, State.Retry);
		}

		private void Reinitialize(Protocol protocol, ProtocolConfig config, State state)
		{
			if (protocol.HandshakePattern.Patterns.Count() == 1)
			{
				throw new ArgumentException("One-way patterns are not yet supported.");
			}

			if (transport != null)
			{
				throw new InvalidOperationException($"Cannot change protocol after the handshake has been completed.");
			}

			if (this.state != State.Initial)
			{
				throw new InvalidOperationException($"Cannot change protocol more than once.");
			}

			this.protocol = protocol;
			this.config = config;
			this.state = state;

			if (handshakeState != null)
			{
				handshakeState.Dispose();
				handshakeState = null;
			}

			isNextMessageEncrypted = IsInitialMessageEncrypted(protocol);
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

			ProcessMessage(HandshakeOperation.WriteNegotiationData, negotiationData);
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
				var (bytesWritten, handshakeHash, transport) = handshakeState.WriteMessage(plaintext.Span, ciphertext.Span);
				isNextMessageEncrypted = true;

				if (transport != null)
				{
					handshakeState.Dispose();
					handshakeState = null;

					this.handshakeHash = handshakeHash;
					this.transport = transport;
				}

				WritePacket(negotiationData.Span, buffer);
				BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(negotiationLength), (ushort)bytesWritten);
				ProcessMessage(HandshakeOperation.WriteHandshakeMessage, ciphertext.Slice(0, bytesWritten));

				int noiseLength = LenFieldSize + bytesWritten;
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
		/// Called by the server when rejecting the initial protocol, or requesting a retry from the client.
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
		public async Task WriteEmptyHandshakeMessageAsync(Memory<byte> negotiationData = default, CancellationToken cancellationToken = default)
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

			ProcessMessage(HandshakeOperation.WriteNegotiationData, negotiationData);
			ProcessMessage(HandshakeOperation.WriteHandshakeMessage, Memory<byte>.Empty, false);

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
			ProcessMessage(HandshakeOperation.ReadNegotiationData, negotiationData);

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
			ProcessMessage(HandshakeOperation.ReadHandshakeMessage, noiseMessage, false);

			if (noiseMessage.Length == 0)
			{
				return empty;
			}

			var plaintext = new byte[noiseMessage.Length];
			var (bytesRead, handshakeHash, transport) = handshakeState.ReadMessage(noiseMessage, plaintext);

			if (transport != null)
			{
				handshakeState.Dispose();
				handshakeState = null;

				this.handshakeHash = handshakeHash;
				this.transport = transport;
			}

			if (isNextMessageEncrypted)
			{
				return ReadPacket(plaintext.AsSpan(0, bytesRead));
			}

			isNextMessageEncrypted = true;
			return plaintext.AsSpan(0, bytesRead).ToArray();
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
			ProcessMessage(HandshakeOperation.ReadHandshakeMessage, noiseMessage, false);
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

			// Handshake messages might still be saved here (for example, in the
			// Accept or Switch cases where Alice is using a one-way pattern). The
			// handshake is complete at this moment, so we no longer have to keep them.
			savedMessages = null;

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

			// Handshake messages might still be saved here (for example, in the
			// Accept or Switch cases where Alice is using a one-way pattern). The
			// handshake is complete at this moment, so we no longer have to keep them.
			savedMessages = null;

			var noiseMessage = await ReadPacketAsync(stream, cancellationToken).ConfigureAwait(false);
			var minSize = LenFieldSize + TagSize;

			if (noiseMessage.Length < minSize)
			{
				throw new ArgumentException($"Transport message must be greater than or equal to {minSize} bytes in length.");
			}

			var read = transport.ReadMessage(noiseMessage, noiseMessage);

			return ReadPacket(noiseMessage.AsSpan(0, read));
		}

		/// <summary>
		/// Sets the function to be called after the handshake state
		/// is created. It should only be used from NoiseSocket.Tests
		/// to fix the ephemeral private key.
		/// </summary>
		internal void SetInitializer(Action<HandshakeState> initializer)
		{
			this.initializer = initializer;
		}

		private void ProcessMessage(HandshakeOperation operation, Memory<byte> data, bool copy = true)
		{
			var next = Next(lastOperation);

			if (next != operation)
			{
				throw new InvalidOperationException($"Expected the call to {next}, but {operation} was called instead.");
			}

			lastOperation = operation;

			if (savedMessages != null && savedMessages.Count < MaxSavedMessagesCount)
			{
				savedMessages.Add(copy ? data.ToArray() : data);
			}
			else
			{
				savedMessages = null;
			}
		}

		private HandshakeState InitializeHandshakeState()
		{
			if (protocol == null)
			{
				string error = $"Cannot perform the handshake before calling either {nameof(Accept)}, {nameof(Switch)}, or {nameof(Retry)}.";
				throw new InvalidOperationException(error);
			}

			ThrowIfPrologueInvalid();

			byte[] noiseSocketInit = noiseSocketInit1;

			switch (state)
			{
				case State.Switch: noiseSocketInit = noiseSocketInit2; break;
				case State.Retry: noiseSocketInit = noiseSocketInit3; break;
			}

			var prologue = config.Prologue.AsSpan();
			var length = noiseSocketInit.Length + savedMessages.Sum(message => LenFieldSize + message.Length) + prologue.Length;
			var pool = ArrayPool<byte>.Shared;
			var buffer = pool.Rent(length);

			try
			{
				noiseSocketInit.AsSpan().CopyTo(buffer);
				var next = buffer.AsSpan(noiseSocketInit.Length);

				foreach (var message in savedMessages)
				{
					WritePacket(message.Span, next);
					next = next.Slice(LenFieldSize + message.Length);
				}

				if (state == State.Switch || state == State.Retry)
				{
					savedMessages = null;
				}

				prologue.CopyTo(next);

				var handshakeState = protocol.Create(
					config.Initiator,
					buffer.AsSpan(0, length),
					config.LocalStatic,
					config.RemoteStatic,
					config.PreSharedKeys
				);

				initializer?.Invoke(handshakeState);
				return handshakeState;
			}
			finally
			{
				pool.Return(buffer);
			}
		}

		private bool IsPrologueValid()
		{
			if (savedMessages == null)
			{
				return false;
			}

			if (state == State.Initial || state == State.Accept)
			{
				// The initial negotiation_data_len
				// The initial negotiation_data

				return savedMessages.Count == 1;
			}

			if (state == State.Switch)
			{
				// The initial negotiation_data_len
				// The initial negotiation_data
				// The initial noise_message_len
				// The initial noise_message
				// The responding negotiation_data_len
				// The responding negotiation_data

				return savedMessages.Count == 3;
			}

			if (state == State.Retry)
			{
				// The initial negotiation_data_len
				// The initial negotiation_data
				// The initial noise_message_len
				// The initial noise_message
				// The responding negotiation_data_len
				// The responding negotiation_data
				// The responding noise_message_len (two bytes of zeros)
				// The responding noise_message (zero-length, shown for completeness)
				// The retry negotiation_data_len
				// The retry negotiation_data

				return savedMessages.Count == 5;
			}

			return false;
		}

		private static HandshakeOperation Next(HandshakeOperation operation)
		{
			switch (operation)
			{
				case HandshakeOperation.ReadNegotiationData: return HandshakeOperation.ReadHandshakeMessage;
				case HandshakeOperation.WriteNegotiationData: return HandshakeOperation.WriteHandshakeMessage;
				case HandshakeOperation.ReadHandshakeMessage: return HandshakeOperation.WriteNegotiationData;
				case HandshakeOperation.WriteHandshakeMessage: return HandshakeOperation.ReadNegotiationData;
				default: throw new InvalidOperationException("Unknown handshake operation.");
			}
		}

		private void ThrowIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(NoiseSocket));
			}
		}

		private void ThrowIfPrologueInvalid()
		{
			if (!IsPrologueValid())
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

			if (data.Length > 0)
			{
				await stream.ReadAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
			}

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

		private enum State
		{
			Initial,
			Accept,
			Switch,
			Retry
		}

		private enum HandshakeOperation
		{
			ReadNegotiationData,
			WriteNegotiationData,
			ReadHandshakeMessage,
			WriteHandshakeMessage
		}
	}
}
