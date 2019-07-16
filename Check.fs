module Check

open System
open System.IO
open FSharp.Control
open FSharp.Data
open FSharp.Interop.Compose.Linq
open FSharp.Interop.NullOptAble
open FSharp.Interop.NullOptAble.Operators

type SslLabsHost = JsonProvider<"Sample.json">
let baseUrl = "https://api.ssllabs.com/api/v3"

[<Flags>]
type ErrorStatus = Okay = 0 
                   | Expiring = 1 
                   | GradeB = 2 
                   | CertIssue = 4 
                   | NotGradeAOrB = 8 
                   | Expired = 16 
                   | ExceptionThrown = 32

[<Flags>]
type CertIssue = Okay = 0
                 | NoChainOfTrust = 1
                 | NotBeforeDate =2
                 | NotAfter = 4
                 | HostnameMismatch = 8
                 | Revoked = 16
                 | BadCommonName = 32
                 | SelfSigned = 64
                 | Blacklisted = 128
                 | InsecureSignature = 256
                 | InsecureKey = 512

let prePolling = 5_000
let inProgPolling = 10_000

let asyncNoOp = lazy Async.Sleep 0


//Setup Console initial state and functions
let originalColor = Console.ForegroundColor
Console.OutputEncoding <- System.Text.Encoding.UTF8;

let consoleWriter (lineEnd:string) (color:ConsoleColor) fmt =
    let write (s:string) =
        Console.ForegroundColor <- color
        Console.Write(s+lineEnd)
        Console.ForegroundColor <- originalColor
    Printf.kprintf write fmt

let consoleN fmt = consoleWriter Environment.NewLine originalColor fmt 
let console fmt = consoleWriter String.Empty originalColor fmt 
let consoleColorN color fmt = consoleWriter Environment.NewLine color fmt 
let consoleColor color fmt = consoleWriter String.Empty color fmt 


//Check host list against SSLLabs.com
let sslLabs (optOutputDir: string option) (hosts:string seq) =
    async {
        let! es =
            asyncSeq{
               
                for host in hosts do
                    let polledData = asyncSeq {
                        let mutable startNew = "on"
                        while true do
                            let! data = SslLabsHost.AsyncLoad(sprintf "%s/analyze?host=%s&startNew=%s&all=done" baseUrl host startNew)
                            startNew <- "off"
                            match data.Status with
                                | "DNS" -> do! Async.Sleep prePolling
                                | "IN_PROGRESS" -> do! Async.Sleep inProgPolling
                                | "READY" -> yield data
                                | _ -> 
                                      let statusMessage = data.JsonValue.Item("statusMessage").ToString()
                                      raise (Exception(sprintf "Error Analyzing %s - %s" host statusMessage))
                    }
                    try 
                        let l,t = Console.CursorLeft, Console.CursorTop
                        let startTime = DateTime.UtcNow
                        consoleN "%s ..." host
                        let! finalData = polledData |> AsyncSeq.tryFirst
                        Console.SetCursorPosition(l,t)
                        consoleN "%s (%O): " host (DateTime.UtcNow - startTime)
                        //If output directory specified, write out json data.
                        do!
                            option {
                                        let! data = finalData
                                        let! outDir = optOutputDir
                                        let outPath = Path.Combine(outDir, sprintf "%s.json" host)
                                        return File.WriteAllTextAsync(outPath, data.JsonValue.ToString()) |> Async.AwaitTask
                            } |?-> asyncNoOp

                        let hostEs =  
                            chooseSeq {
                                let! data = finalData
                                //Process Certs to find leafs
                                let certMap = 
                                    data.Certs
                                        |> Enumerable.toLookup (fun k->k.Subject)
                                        |> Seq.map (fun l -> l.Key, l :> seq<_>)
                                        |> Map.ofSeq
                                let rootSubjects = data.Certs |> Seq.map (fun c->c.IssuerSubject)
                                let leafCerts = certMap |> Seq.foldBack Map.remove rootSubjects
                                //Check Expiration and errors of Leaf Certificates
                                for cert in leafCerts |> Map.toSeq |> Seq.collect snd do
                                    let startDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotBefore)
                                    let endDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotAfter)
                                    let issue:CertIssue = enum cert.Issues
                                    //Ignore certs not for this domain
                                    if not <| issue.HasFlag(CertIssue.HostnameMismatch) then
                                        let cn = cert.CommonNames |> Seq.head
                                        consoleN "  Certificate '%s' %s %i bit:" cn cert.KeyAlg cert.KeySize
                                        let expireSpan = endDate - DateTimeOffset DateTime.UtcNow
                                        let warningSpan = if endDate - startDate > TimeSpan.FromDays 90.0 then
                                                              TimeSpan.FromDays 90.0
                                                          else
                                                              TimeSpan.FromDays 30.0
                                        //Check for Issues
                                        if issue <> CertIssue.Okay then
                                            console "    Problem(s): "
                                            consoleColorN ConsoleColor.DarkRed "%A" issue
                                            yield ErrorStatus.CertIssue
                                        //Check Expiration of Cert
                                        let status, color, label =
                                            if expireSpan <=TimeSpan.FromDays 0.0 then
                                                ErrorStatus.Expired, ConsoleColor.DarkRed, "Expired"
                                            elif expireSpan <= warningSpan then
                                                ErrorStatus.Expiring, ConsoleColor.DarkYellow, "Expires"
                                            else
                                                ErrorStatus.Okay, ConsoleColor.DarkGreen, "Expires"
                                        
                                        console "    %s: " label
                                        let expiration = expireSpan.Days;
                                        if expiration > 0 then
                                            consoleColorN color "%i days from today" expiration
                                        else
                                            consoleColorN color "%i days ago" <| abs(expiration)
                                        yield status  

                                let (|Grade|_|) (g:string) (i:string) = if i.Contains(g) then Some () else None
                                
                                for ep in data.Endpoints do
                                    consoleN "  Endpoint '%s': " ep.IpAddress
                                    let status, color = 
                                        match (ep.Grade) with
                                        | Grade "A" -> ErrorStatus.Okay, ConsoleColor.DarkGreen
                                        | Grade "B" -> ErrorStatus.GradeB, ConsoleColor.DarkYellow
                                        | _ -> ErrorStatus.NotGradeAOrB, ConsoleColor.DarkRed
                                    console "    Grade: "
                                    consoleColorN color "%s" ep.Grade
                                    yield status

                            } |> Seq.fold (|||) ErrorStatus.Okay
                        if hostEs <> ErrorStatus.Okay then
                            consoleN "  Has Error(s): %A" hostEs
                        consoleN "  Details:"
                        consoleN "    https://www.ssllabs.com/ssltest/analyze.html?d=%s" host
                        yield hostEs
                    with ex -> 
                        consoleN "Unexpected Error (%s)" host
                        consoleN "  Result: %A" ErrorStatus.ExceptionThrown
                        let rec printExn : exn -> unit =
                            function
                                     | null -> ()
                                     | :? AggregateException as multiEx -> 
                                            for ie in multiEx.Flatten().InnerExceptions do
                                                printExn ie
                                     | singleEx -> 
                                        consoleN "%s" singleEx.Message
                                        consoleN "%s" singleEx.StackTrace
                                        printExn singleEx
                        printExn ex
                        yield ErrorStatus.ExceptionThrown
            } |> AsyncSeq.fold (|||) ErrorStatus.Okay
        if es = ErrorStatus.Okay then
            consoleN "All Clear 😃."
        else
            let scream = "😱"
            let frown = "😦"
            consoleN "Found Error(s) %s: %A" (if es <= ErrorStatus.GradeB then frown else scream) es
        return int es
    }