﻿(*
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
open FSharp.Interop.Compose.System
open FSharp.Interop.NullOptAble
open FSharp.Interop.NullOptAble.Operators

module Hdr = FSharp.Data.HttpRequestHeaders
type SslLabsHost = JsonProvider<"samples/host.json">
type SslLabsInfo = JsonProvider<"samples/info.json">
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
type IJsonDocument = FSharp.Data.Runtime.BaseTypes.IJsonDocument
let parseSslLabsError = 
    function | "READY" -> Ready 
             | "DNS" -> Dns 
             | "IN_PROGRESS" -> InProgress 
             | _ -> Error
let toIJsonDocOption target : IJsonDocument option =
    target |> Option.map (fun x-> upcast x)

//Constants suggestion from the api docs
// https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#access-rate-and-rate-limiting
let baseUrl = "https://api.ssllabs.com/api/v3"
let appUrl = "https://www.ssllabs.com/ssltest/analyze.html"
let prePolling = 5_000
let inProgPolling = 10_000
let private random = Random()
let serviceUnavailablePolling () =
    random.Next(15_000, 30_000)
    |> float
    |> TimeSpan.FromMilliseconds
let serviceOverloadedPolling () =
    random.Next(30_000, 45_000)
    |> float
    |> TimeSpan.FromMilliseconds

//Setup Console initial state and functions
let originalColor = Console.ForegroundColor
type ResultStream =
    | ConsoleColorText of string * ConsoleColor
    | AddStatus of ErrorStatus
let private consoleStreamWriter (lineEnd:string) (color:ConsoleColor)  fmt =
    let write (s:string) =
        ConsoleColorText(s + lineEnd, color)
    Printf.kprintf write fmt
let consoleN fmt = consoleStreamWriter Environment.NewLine originalColor fmt
let consoleNN fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine) originalColor fmt 
let console fmt = consoleStreamWriter String.Empty originalColor fmt 
let consoleColorN color fmt = consoleStreamWriter Environment.NewLine color fmt 
let consoleColorNN color fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine)  color fmt 
let consoleColor color fmt = consoleStreamWriter String.Empty color fmt 
let private consoleMonitor = obj()
let stdoutOrStatus (result:ResultStream) =
    match result with
    | ConsoleColorText(s, color) ->
        lock(consoleMonitor) (
            fun () ->
                Console.ForegroundColor <- color
                Console.Write(s)
                Console.ForegroundColor <- originalColor
                ErrorStatus.Okay
        )
    | AddStatus e -> e
let stdout (result:ResultStream) =
    result |> stdoutOrStatus |> ignore

// Global Assement quote variable to track when to slow down assessments when there are too many
let assessmentTrack = ref (0,0)
let updateAssessmentReq curr max =
    lock assessmentTrack (fun () -> assessmentTrack := curr,max)
let checkAllowedNewAssessment () =
    lock assessmentTrack (
        fun () ->
            let curr,max = !assessmentTrack
            if max <= 0 then
                failwithf "Service is not allowing you to request new assessments (%i, %i). " curr max
            else
                curr < max
    )

// HTTP Request Code
let assmVer = System.Reflection.Assembly.GetEntryAssembly().GetName().Version
let userAgent = sprintf "dotnet-ssllabs-check v%O" assmVer
let private parseReq parseF resp =
    let body = resp.Body 
    let max = int resp.Headers.["X-Max-Assessments"];
    let curr = int resp.Headers.["X-Current-Assessments"] 
    updateAssessmentReq curr max
    match body with
    | Text text -> 
        {|
            Data = option { if resp.StatusCode = HttpStatusCodes.OK then return parseF text}
            Status = resp.StatusCode
        |}
    | _ -> failwith "Request did not return text";
let request parseF api  = async {
        let! resp = Http.AsyncRequest(baseUrl + api, headers = [Hdr.UserAgent userAgent], silentHttpErrors = true)
        return parseReq parseF resp
    }
let requestQ parseF api q = async{
        let! resp = Http.AsyncRequest(baseUrl + api, q, headers = [Hdr.UserAgent userAgent], silentHttpErrors = true)
        return parseReq parseF resp
    }
let failWithHttpStatus status = failwithf "Service Returned HTTP Status %i" status
let hostJsonProcessor (data: SslLabsHost.Root option) =  
    chooseSeq {
        let! data' = data
        //Process Certs to find leafs
        let certMap = 
            data'.Certs
                |> Enumerable.toLookup (fun k->k.Subject)
                |> Seq.map (fun l -> l.Key, l :> seq<_>)
                |> Map.ofSeq
        let rootSubjects = data'.Certs |> Seq.map (fun c->c.IssuerSubject)
        let leafCerts = certMap |> Seq.foldBack Map.remove rootSubjects
        //Check Expiration and errors of Leaf Certificates
        let leafCerts' = leafCerts |> Map.toSeq |> Seq.collect snd |> Seq.indexed 
        for i,cert in leafCerts' do
            let startDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotBefore)
            let endDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotAfter)
            let issue:CertIssue = enum cert.Issues
            //Ignore certs not for this domain
            if not <| issue.HasFlag(CertIssue.HostnameMismatch) then
                yield consoleN "  Certificate #%i %s %i bit:" (i+1) cert.KeyAlg cert.KeySize
                yield consoleN "    CN: %s" (cert.CommonNames |> String.join ", ")
                let expireSpan = endDate - DateTimeOffset DateTime.UtcNow
                let warningSpan = if endDate - startDate > TimeSpan.FromDays 90.0 then
                                        TimeSpan.FromDays 90.0
                                    else
                                        TimeSpan.FromDays 30.0
                //Check for Issues
                if issue <> CertIssue.Okay then
                    yield console "    Problem(s): "
                    yield consoleColorN ConsoleColor.DarkRed "%A" issue
                    yield AddStatus ErrorStatus.CertIssue
                //Check Expiration of Cert
                let status, color, label =
                    if expireSpan <=TimeSpan.FromDays 0.0 then
                        ErrorStatus.Expired, ConsoleColor.DarkRed, "Expired"
                    elif expireSpan <= warningSpan then
                        ErrorStatus.Expiring, ConsoleColor.DarkYellow, "Expires"
                    else
                        ErrorStatus.Okay, ConsoleColor.DarkGreen, "Expires"
                               
                yield console "    %s: " label
                let expiration = expireSpan.Days;
                if expiration > 0 then
                    yield consoleColorN color "%i days from today" expiration
                else
                    yield consoleColorN color "%i days ago" <| abs(expiration)
                yield AddStatus status  
        let (|Grade|_|) (g:string) (i:string) = if i.Contains(g) then Some () else None
        //Check grades (per endpont & host)
        for ep in data'.Endpoints do
            yield consoleN "  Endpoint '%s': " ep.IpAddress
            let status, color = 
                match (ep.Grade) with
                | Grade "A" -> ErrorStatus.Okay, ConsoleColor.DarkGreen
                | Grade "B" -> ErrorStatus.GradeB, ConsoleColor.DarkYellow
                | _ -> ErrorStatus.NotGradeAOrB, ConsoleColor.DarkRed
            yield console "    Grade: "
            yield consoleColorN color "%s" ep.Grade
            yield AddStatus status
    }
//Check host list against SSLLabs.com
type SslLabConfig = { 
                        OptOutputDir: string option
                        Emoji:        bool
                        VersionOnly:  bool
                        Hosts:        string seq
                        HostFile:     string option
                    }
let sslLabs (config: SslLabConfig) =
    //Configure if showing emoji
    let emoji s = if config.Emoji then s else String.Empty
    if config.Emoji then
        Console.OutputEncoding <- System.Text.Encoding.UTF8

    let writeJsonOutput (fData:IJsonDocument option) identifier =
        let asyncNoOp = lazy Async.Sleep 0
        option {
                let! data = fData
                let! outDir = config.OptOutputDir
                Directory.CreateDirectory outDir |> ignore
                let outPath = Path.Combine(outDir, sprintf "%s.json" identifier)
                return File.WriteAllTextAsync(outPath, data.JsonValue.ToString()) |> Async.AwaitTask
        } |?-> asyncNoOp

    //Main Logic
    async {
        //Print out SSL Labs Info
        let! info = request SslLabsInfo.Parse "/info"
        let newCoolOff, cur1st, max1st =
            match info.Data with
            | Some i ->
                stdout <| consoleNN "%s - Unofficial Client - (engine:%s) (criteria:%s)" userAgent i.EngineVersion i.CriteriaVersion
                for m in i.Messages do
                    stdout <| consoleNN "%s" m
                i.NewAssessmentCoolOff,i.CurrentAssessments,i.MaxAssessments
            | None -> 
                stdout <| consoleNN "%s - Unofficial Client - service unavailable" userAgent
                failWithHttpStatus info.Status
        updateAssessmentReq cur1st max1st

        //get host from arguments or file
        let! hosts = option {
                        let! hostFile = config.HostFile
                        return async {
                            let! contents = File.ReadAllLinesAsync hostFile |> Async.AwaitTask
                            return contents |> Array.toSeq
                        }
                     } |?-> lazy (async { return config.Hosts })

        if config.VersionOnly then
            stdout <| consoleNN "Assessments Available %i of %i" cur1st max1st
            return int ErrorStatus.Okay
        else
            stdout <| consoleNN "Started: %O" DateTime.Now
            stdout <| consoleN "Hosts to Check:"
            for host in hosts do
                stdout <| consoleN " %s" host
            stdout <| consoleN ""
            //If output directory specified, write out json data.
            do! writeJsonOutput (info.Data |> toIJsonDocOption) "info"

            //polling data for a single host
            let rec pollUntilData startQ i host= asyncSeq {
                do! Async.Sleep <| newCoolOff * i
                if not <| checkAllowedNewAssessment () then
                    yield! pollUntilData startQ (i + 1) host
                else
                    let! analyze = requestQ SslLabsHost.Parse "/analyze" <| ["host", host; "all", "done"] @ startQ
                    match analyze.Data with
                    | Some data ->
                        let status = parseSslLabsError data.Status
                        match status with
                            | Error -> 
                                  let statusMessage = data.JsonValue.Item("statusMessage").ToString()
                                  failwithf "Error Analyzing %s - %s" host statusMessage
                            | Ready ->
                                yield data
                            | Dns -> 
                                do! Async.Sleep prePolling
                                yield! pollUntilData [] 0 host
                            | InProgress ->
                                do! Async.Sleep inProgPolling
                                yield! pollUntilData [] 0 host
                    | None ->
                        match analyze.Status with
                        | HttpStatusCodes.TooManyRequests ->
                            yield! pollUntilData startQ i host
                        | HttpStatusCodes.ServiceUnavailable  -> 
                            let delay = serviceUnavailablePolling ()
                            delay 
                                |> consoleNN "Service Unavailable trying again for '%s' in %O." host
                                |> stdout
                            do! Async.Sleep <| delay.Milliseconds
                            yield! pollUntilData startQ i host
                        | 529 (* overloaded *)  -> 
                            let delay = serviceOverloadedPolling ()
                            delay
                                |> consoleNN "Service Unavailable trying again for '%s' in %O." host
                                |> stdout 
                            do! Async.Sleep <| delay.Milliseconds
                            yield! pollUntilData startQ i host
                        | x -> failWithHttpStatus x
            }

            //processHost -- indexed for bulk offset
            let parallelProcessHost (i, host)  = asyncSeq {
                try 
                    let startTime = DateTime.UtcNow
                    let! data = 
                        pollUntilData ["startNew","on"] (i + 1) host
                        |> AsyncSeq.tryFirst
                    //If output directory specified, write out json data.
                    do! writeJsonOutput (data |> toIJsonDocOption) host
                    //Process host results
                    let hostResults = data |> hostJsonProcessor
                    yield consoleN "%s (%O): " host (DateTime.UtcNow - startTime)
                    yield! AsyncSeq.ofSeq hostResults
                    let hostEs = 
                        hostResults
                        |> Seq.choose (function|AddStatus e->Some e|_->None)
                        |> Seq.fold (|||) ErrorStatus.Okay
                    //Error Summary
                    if hostEs <> ErrorStatus.Okay then
                        yield consoleN "  Has Error(s): %A" hostEs
                    //SSL Labs link
                    yield consoleN "  Details:"
                    yield consoleColorNN ConsoleColor.Blue "    %s?d=%s" appUrl host
                with ex -> 
                    yield consoleN "%s (Unexpected Error):" host
                    yield consoleN "  Has Error(s): %A" ErrorStatus.ExceptionThrown
                    yield consoleN "--------------"
                    let rec printExn : exn -> ResultStream seq =
                        function
                                 | null -> Seq.empty
                                 | :? AggregateException as multiEx -> 
                                        seq {
                                            for ie in multiEx.Flatten().InnerExceptions do
                                                yield! printExn ie
                                        }
                                 | singleEx -> 
                                    seq {
                                        yield consoleN "%s" singleEx.Message
                                        yield consoleN "%s" singleEx.StackTrace
                                        yield! printExn singleEx.InnerException
                                    }
                    yield! AsyncSeq.ofSeq <| printExn ex
                    yield consoleNN "--------------"
                    yield AddStatus ErrorStatus.ExceptionThrown
                }

            let! es = 
                hosts
                |> Seq.indexed
                |> AsyncSeq.ofSeq
                |> AsyncSeq.map parallelProcessHost
                |> AsyncSeq.mapAsyncParallel AsyncSeq.toListAsync 
                |> AsyncSeq.collect AsyncSeq.ofSeq
                |> AsyncSeq.map stdoutOrStatus //Write out to console
                |> AsyncSeq.fold (|||) ErrorStatus.Okay

            stdout <| consoleN "Completed: %O" DateTime.Now
            //Final Error Summary
            if es = ErrorStatus.Okay then
                stdout <| consoleN "All Clear%s." (emoji " 😃")
            else
                let scream = emoji " 😱"
                let frown = emoji " 😦"
                stdout <| consoleN "Found Error(s)%s: %A" (if es <= ErrorStatus.GradeB then frown else scream) es
            return int es
    }