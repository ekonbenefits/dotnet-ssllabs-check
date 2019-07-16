(*
   Copyright 2019 Ekon Benefits

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*)
module Check

open System
open System.IO
open FSharp.Control
open FSharp.Data
open FSharp.Interop.Compose.Linq
open FSharp.Interop.NullOptAble
open FSharp.Interop.NullOptAble.Operators

type SslLabsHost = JsonProvider<"samples/host.json">
type SslLabsInfo = JsonProvider<"samples/info.json">

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

type SslLabsError = 
    Ready
    | Dns
    | InProgress
    | Error

let parseSslLabsError = 
    function | "READY" -> Ready 
             | "DNS" -> Dns 
             | "IN_PROGRESS" -> InProgress 
             | _ -> Error

//Polling suggestion from the api docs 
//https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#access-rate-and-rate-limiting
let prePolling = 5_000
let inProgPolling = 10_000

let asyncNoOp = lazy Async.Sleep 0


//Setup Console initial state and functions
let originalColor = Console.ForegroundColor

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

type SslLabConfig = { OptOutputDir: string option; Emoji: bool}

//Check host list against SSLLabs.com
let sslLabs (config: SslLabConfig) (hosts:string seq) =
    //Configure if showing emoji
    let emoji s = if config.Emoji then s else String.Empty
    if config.Emoji then
        Console.OutputEncoding <- System.Text.Encoding.UTF8
    //Main Logic
    async {
        
        //Print out SSL Labs Info
        let! info = SslLabsInfo.AsyncLoad(sprintf "%s/info" baseUrl)
        consoleN "ssllabs-check Unofficial Client (engine:%s) (criteria:%s)" info.EngineVersion info.CriteriaVersion
        consoleN ""
        for m in info.Messages do
            consoleN "%s" m
            consoleN ""

        let! es =
            asyncSeq {
                for host in hosts do
                    //I was unsure with asyncSeq if this construction would produced unlimited stack frames,
                    //IL was too complicated, ran debugger on slow site (over 7 minutes of polling)
                    //stack was quite shallow!!
                    let rec polledData startNew = asyncSeq {
                        let analyze = sprintf "%s/analyze?host=%s&startNew=%s&all=done"
                        let! data = SslLabsHost.AsyncLoad(analyze baseUrl host startNew)
                        let status = parseSslLabsError data.Status
                        match status with
                            | Error -> 
                                  let statusMessage = data.JsonValue.Item("statusMessage").ToString()
                                  raise (Exception(sprintf "Error Analyzing %s - %s" host statusMessage))
                            | Ready -> yield data
                            | Dns -> 
                                do! Async.Sleep prePolling
                                yield! polledData "off"
                            | InProgress -> 
                                do! Async.Sleep inProgPolling
                                yield! polledData "off"
                    }
                    try 
                        let oldPos = Console.CursorLeft, Console.CursorTop
                        let startTime = DateTime.UtcNow
                        consoleN "%s ..." host
                        let! finalData = polledData "on" |> AsyncSeq.tryFirst
                        Console.SetCursorPosition(oldPos)
                        consoleN "%s (%O): " host (DateTime.UtcNow - startTime)
                        //If output directory specified, write out json data.
                        do!
                            option {
                                        let! data = finalData
                                        let! outDir = config.OptOutputDir
                                        Directory.CreateDirectory outDir |> ignore
                                        let outPath = Path.Combine(outDir, sprintf "%s.json" host)
                                        return File.WriteAllTextAsync(outPath, data.JsonValue.ToString()) |> Async.AwaitTask
                            } |?-> asyncNoOp
                        //Check a single Host and bitwise OR error codes.
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
                                //Check grades (per endpont & host)
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
                        //Error Summary
                        if hostEs <> ErrorStatus.Okay then
                            consoleN "  Has Error(s): %A" hostEs
                        //SSL Labs link
                        consoleN "  Details:"
                        consoleColorN ConsoleColor.DarkBlue "    https://www.ssllabs.com/ssltest/analyze.html?d=%s" host
                        //yield host error codes to be bitwise or'd into final summary
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
        //Final Error Summary
        if es = ErrorStatus.Okay then
            consoleN "All Clear%s." (emoji " 😃")
        else
            let scream = emoji " 😱"
            let frown = emoji " 😦"
            consoleN "Found Error(s)%s: %A" (if es <= ErrorStatus.GradeB then frown else scream) es
        return int es
    }