![](NoiseSocket.png)

[![Latest Version](https://img.shields.io/nuget/v/NoiseSocket.NET.svg)](https://www.nuget.org/packages/NoiseSocket.NET)
[![Build Status](https://travis-ci.org/Metalnem/noisesocket.svg?branch=master)](https://travis-ci.org/Metalnem/noisesocket)
[![Build status](https://ci.appveyor.com/api/projects/status/i52hlnib699m5lra?svg=true)](https://ci.appveyor.com/project/Metalnem/noisesocket)
[![Docs](https://img.shields.io/badge/docs-API-orange.svg?style=flat)](https://metalnem.github.io/noisesocket/api/Noise.NoiseSocket.html)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/noisesocket/master/LICENSE)

.NET Standard 1.3 implementation of the [NoiseSocket Protocol]
(revision 2 of the spec).

>NoiseSocket provides an encoding layer for the
>[Noise Protocol Framework]. NoiseSocket can encode Noise messages
>and associated negotiation data into a form suitable for
>transmission over reliable, stream-based protocols such as TCP.
>
>NoiseSocket doesn't specify the contents of negotiation data,
>since different applications will encode and advertise protocol
>support in different ways. NoiseSocket just defines a message
>format to transport this data, and APIs to access it.

[NoiseSocket Protocol]: https://noiseprotocol.org/specs/noisesocket.html
[Noise Protocol Framework]: https://noiseprotocol.org/

## Samples

[Acceptance] (using [TcpClient] and [TcpListener])  
[Switch protocol] (using ordinary [Socket])  
[Retry request] (using [NamedPipeClientStream] and [NamedPipeServerStream])

[Acceptance]: https://github.com/Metalnem/noisesocket/blob/master/NoiseSocket.Examples/AcceptExample.cs
[Switch protocol]: https://github.com/Metalnem/noisesocket/blob/master/NoiseSocket.Examples/SwitchExample.cs
[Retry request]: https://github.com/Metalnem/noisesocket/blob/master/NoiseSocket.Examples/RetryExample.cs
[TcpClient]: https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient?view=netstandard-2.0
[TcpListener]: https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcplistener?view=netstandard-2.0
[Socket]: https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.socket?view=netstandard-2.0
[NamedPipeClientStream]: https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeclientstream?view=netstandard-2.0
[NamedPipeServerStream]: https://docs.microsoft.com/en-us/dotnet/api/system.io.pipes.namedpipeserverstream?view=netstandard-2.0

## Installation

```
> dotnet add package NoiseSocket.NET --version 0.9.1
```
