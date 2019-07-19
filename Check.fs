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
type ConsoleLevel = 
    Error
    | Warn
    | Info
    | Progress
    | Debug
    | Trace

type IJsonDocument = FSharp.Data.Runtime.BaseTypes.IJsonDocument
let parseSslLabsError = 
    function | "READY" -> Ready 
             | "DNS" -> Dns 
             | "IN_PROGRESS" -> InProgress 
             | _ -> SslLabsError.Error
let parseConsoleError = 
    String.toLower >>
    function | "error" -> ConsoleLevel.Error 
             | "warn" -> Warn
             | "trace" -> Trace 
             | "debug" -> Debug
             | "progress" -> Progress 
             | _ -> Info
let levelForErrorStatus errorStatus =
    if errorStatus = ErrorStatus.Okay then
        Info
    elif errorStatus <= ErrorStatus.GradeB then
        Warn
    else
        Error
let toIJsonDocOption target : IJsonDocument option =
    target |> Option.map (fun x-> upcast x)
module Async =
    let sleepTimeSpan (time:TimeSpan) =
        Async.Sleep (int time.TotalMilliseconds)

//Constants suggestion from the api docs
// https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md#access-rate-and-rate-limiting
let builtInBaseUrl = "https://api.ssllabs.com/api/v3"
let appUrl = "https://www.ssllabs.com/ssltest/analyze.html"
let prePolling = TimeSpan.FromSeconds(5.0)
let inProgPolling = TimeSpan.FromSeconds(10.0)
let private random = Random()
let serviceUnavailablePolling () =
    random.Next(15, 30)
    |> float
    |> TimeSpan.FromMinutes
let serviceOverloadedPolling () =
    random.Next(30, 45)
    |> float
    |> TimeSpan.FromMinutes
let tooManyReqPolling () =
    random.Next(5, 20)
    |> float
    |> TimeSpan.FromSeconds

//Setup Console initial state and functions
let originalColor = Console.ForegroundColor
type ResultStream =
    | NoOp
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
let stdoutOrStatusBy (optLevel, specifiedLevel) (result:ResultStream) =
    match result with
    | ConsoleColorText(s, color) ->
        if specifiedLevel <= optLevel then
            lock(consoleMonitor) (
                fun () ->
                    Console.ForegroundColor <- color
                    Console.Write(s)
                    Console.ForegroundColor <- originalColor
            )
        None
    | AddStatus e -> Some e
    | NoOp  -> None
let stdoutBy (optLevel, specifiedLevel) (result:ResultStream) =
    result |> stdoutOrStatusBy (optLevel, specifiedLevel) |> ignore

// Global Assement quote variable to track when to slow down assessments when there are too many
let assessmentTrack = ref (0,0)
let updateAssessmentReq curr max =
    lock assessmentTrack (fun () -> assessmentTrack := curr,max)
let checkAllowedNewAssessment () =
    let curr,max = lock assessmentTrack (fun () -> !assessmentTrack)
    if max <= 0 then
        failwithf "Service is not allowing you to request new assessments (%i, %i). " curr max
    else
        {| Allowed = curr < max; Current = curr; Max = max|}

// HTTP Request Code
let assmVer = System.Reflection.Assembly.GetEntryAssembly().GetName().Version
let userAgent = sprintf "dotnet-ssllabs-check v%O" assmVer
let private parseReq parseF resp =
    let body = resp.Body 
    let max = int resp.Headers.["X-Max-Assessments"];
    let curr = int resp.Headers.["X-Current-Assessments"] 
    //Undocumented Client Max Value for Debuging
    let maxClient = resp.Headers.TryFind("X-ClientMaxAssessments")
    updateAssessmentReq curr max
    match body with
    | Text text -> 
        {|
            Data = option { if resp.StatusCode = HttpStatusCodes.OK then return parseF text}
            Status = resp.StatusCode
            Current = curr
            Max = max
            ClientMax = maxClient
        |}
    | _ -> failwith "Request did not return text";
let request baseUrl parseF api  = async {
        let! resp = Http.AsyncRequest(baseUrl + api, headers = [Hdr.UserAgent userAgent], silentHttpErrors = true)
        return parseReq parseF resp
    }
let requestQ baseUrl parseF api q = async{
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
        let leafCerts' = 
            leafCerts 
            |> Map.toSeq 
            |> Seq.collect snd 
            |> Seq.filter (fun c -> not <| (enum<CertIssue> c.Issues).HasFlag(CertIssue.HostnameMismatch))
            |> Seq.indexed 
        for i,cert in leafCerts' do
            let startDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotBefore)
            let endDate = DateTimeOffset.FromUnixTimeMilliseconds(cert.NotAfter)
            let issue:CertIssue = enum cert.Issues
            //Ignore certs not for this domain
            yield consoleN "  Certificate #%i %s %i bit:" (i+1) cert.KeyAlg cert.KeySize
            yield consoleN "    SAN: %s" (cert.AltNames |> String.join ", ")
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
                        Verbosity:    string option
                        API:          string option
                    }
let sslLabs (config: SslLabConfig) =
    //Configure if showing emoji
    let emoji s = if config.Emoji then s else String.Empty
    if config.Emoji then
        Console.OutputEncoding <- System.Text.Encoding.UTF8

    let baseUrl = option { let! api = config.API
                           return api |> String.trimEnd [|'/'|]
                         } |?-> lazy builtInBaseUrl

    let request' = request baseUrl
    let requestQ' = requestQ baseUrl

    //setup some level functions
    let verboseLevel = defaultArg (config.Verbosity |> Option.map parseConsoleError) Progress
    let levelFilter level result = if level <= verboseLevel then result else NoOp
    let stdout = stdoutBy (Trace,Trace) //Always Print
    let stdoutL level = stdoutBy (verboseLevel, level)
    let stdoutOrStatus = stdoutOrStatusBy (Trace,Trace) //Always Print

    let writeJsonOutput (fData:IJsonDocument option) identifier =
        let asyncNoOp = lazy Async.Sleep 0
        option {
                let! data = fData
                let! outDir = config.OptOutputDir
                Directory.CreateDirectory outDir |> ignore
                let outPath = Path.Combine(outDir, sprintf "%s.json" identifier)
                                |> Path.GetFullPath
                stdoutL Trace <| consoleN "%O Writing out json data to %s" DateTime.Now outPath
                return File.WriteAllTextAsync(outPath, data.JsonValue.ToString()) |> Async.AwaitTask
        } |?-> asyncNoOp

    //Main Logic
    async {
        //Print out SSL Labs Info
        let! info = request' SslLabsInfo.Parse "/info"
        let newCoolOff, cur1st, max1st =
            match info.Data with
            | Some i ->
                stdout <| consoleNN "%s - Unofficial Client - (engine:%s) (criteria:%s)"
                              userAgent i.EngineVersion i.CriteriaVersion
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
                            return contents |> Array.toSeq |> Seq.filter (not << String.startsWith "#")
                        }
                     } |?-> lazy (async { return config.Hosts })
        if config.API |> Option.isSome then
            stdoutL Info  <| consoleNN "API: %s" baseUrl
        guard {
            let! outDir = config.OptOutputDir
            stdoutL Info  <| consoleNN "JSON Output Directory: %s" (outDir |> Path.GetFullPath)
        }
        if config.VersionOnly then
            stdoutL Info  <| consoleNN "Assessments Available %i of %i" cur1st max1st
            return int ErrorStatus.Okay
        else
            stdoutL Progress <| consoleNN "Started: %O" DateTime.Now
            stdout  <| consoleN "Hostnames to Check:"
            for host in hosts do
                stdout <| consoleN " %s" host
            stdout  <| consoleN ""
            //If output directory specified, write out json data.
            do! writeJsonOutput (info.Data |> toIJsonDocOption) "info"
            //polling data for a single host
            let rec pollUntilData (state:{|StartQ:(string*string) list; Index:int; Host:string|}) =
                asyncSeq {
                    let newAssess = state.StartQ |> List.isEmpty |> not
                    if newAssess then
                        do! Async.Sleep <| newCoolOff * state.Index
                    let check = checkAllowedNewAssessment ()
                    if newAssess && not check.Allowed then
                        stdoutL Trace
                            <| consoleN "%O Waiting For Assesment Slot '%s'#%i (Available: %i/%i)"
                                   DateTime.Now state.Host state.Index check.Current check.Max
                        do! Async.sleepTimeSpan inProgPolling
                        yield! pollUntilData state
                    else 
                        if newAssess then
                            stdoutL Debug
                                <| consoleN "%O ATTEMPT New Req '%s'#%i (Reqs/Max: %i/%i)"
                                    DateTime.Now state.Host state.Index check.Current check.Max
                        let! analyze = requestQ' SslLabsHost.Parse "/analyze"
                                            <| ["host", state.Host; "all", "done"] @ state.StartQ
                        match analyze.Data with
                        | Some data ->
                            if newAssess then
                                stdoutL Debug
                                    <| consoleN "%O STARTED New Req '%s'#%i (Reqs/Max: %i/%i)"
                                        DateTime.Now state.Host state.Index check.Current check.Max
                            let status = parseSslLabsError data.Status
                            stdoutL Trace
                                <| consoleN "%O POLL for '%s' (Reqs/Max: %i/%i) (HttpStatus:%i) (Status:%A)"
                                    DateTime.Now state.Host analyze.Current analyze.Max analyze.Status status
                            let stateForPolling = {|state with StartQ = List.empty; Index = 0|}
                            match status with
                                | Ready ->
                                    yield data
                                | SslLabsError.Error -> 
                                    let statusMessage = data.JsonValue.Item("statusMessage").ToString()
                                    failwithf "Error Analyzing %s - %s" state.Host statusMessage
                                | Dns -> 
                                    do! Async.sleepTimeSpan prePolling
                                    yield! pollUntilData stateForPolling
                                | InProgress ->
                                    do! Async.sleepTimeSpan inProgPolling
                                    yield! pollUntilData stateForPolling
                        | None ->
                            let reqType = if newAssess then "start" else "poll"
                            stdoutL Debug
                                <| consoleN "%O Request (%s) FAILED for '%s' (Reqs/Max: %i/%i) (HttpStatus:%i) (ClientMax?:%A)"
                                       DateTime.Now reqType state.Host analyze.Current analyze.Max analyze.Status analyze.ClientMax
                            match analyze.Status with
                            | HttpStatusCodes.TooManyRequests ->
                                //Random slow down if we are getting 429, seems to happen sometimes even with new assesment slots
                                do! Async.sleepTimeSpan <| serviceUnavailablePolling ()  
                                yield! pollUntilData state
                            | HttpStatusCodes.ServiceUnavailable  -> 
                                let delay = serviceUnavailablePolling ()
                                //Write out Immediately
                                stdoutL Info 
                                    <| consoleNN "Service Unavailable trying again for '%s' in %O." state.Host delay 
                                do! Async.sleepTimeSpan delay
                                yield! pollUntilData state
                            | 529 (* overloaded *)  -> 
                                let delay = serviceOverloadedPolling ()
                                //Write out Immediately
                                stdoutL Info
                                    <| consoleNN "Service Overloaded trying again for '%s' in %O." state.Host delay
                                do! Async.sleepTimeSpan delay
                                yield! pollUntilData state
                            | x -> failWithHttpStatus x
            }
            //processHost -- indexed for bulk offset
            let parallelProcessHost (i, host)  = asyncSeq {
                try 
                    let stateForRequesting = {|StartQ = ["startNew","on"]; Index = (i + 1); Host = host|}
                    let! data = 
                        pollUntilData stateForRequesting
                            |> AsyncSeq.tryFirst
                    //If output directory specified, write out json data.
                    do! writeJsonOutput (data |> toIJsonDocOption) host
                    //Process host results
                    let hostResults = data |> hostJsonProcessor
                    let hostEs = 
                         hostResults
                         |> Seq.choose (function|AddStatus e->Some e|_->None)
                         |> Seq.fold (|||) ErrorStatus.Okay
                    let hostLevel = levelForErrorStatus hostEs
                    yield levelFilter hostLevel
                           <| consoleN "%s: " host
                    //this intentionally supresses exit status for warning level status if verbosity=Error
                    yield! hostResults |> Seq.map (levelFilter hostLevel) |> AsyncSeq.ofSeq
                    //Error Summary
                    if hostEs <> ErrorStatus.Okay then
                         yield levelFilter hostLevel
                               <| consoleN "  Has Error(s): %A" hostEs
                    //SSL Labs link
                    yield levelFilter hostLevel
                           <| consoleN "  Details:"
                    yield levelFilter hostLevel
                           <| consoleColorNN ConsoleColor.Blue "    %s?d=%s" appUrl host
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
            let startTime = DateTime.UtcNow
            let totalHosts = hosts |> Seq.length
            let! es = 
                hosts
                |> Seq.indexed
                |> AsyncSeq.ofSeq
                |> AsyncSeq.map parallelProcessHost
                |> AsyncSeq.mapAsyncParallelUnordered AsyncSeq.toListAsync
                |> AsyncSeq.indexed
                |> AsyncSeq.map (
                    fun (i, tail) ->
                            (levelFilter Progress
                                <| consoleN "-- %d of %i --- %O --" (i+1L) totalHosts (DateTime.UtcNow - startTime)
                            ) :: tail
                    )
                |> AsyncSeq.collect AsyncSeq.ofSeq
                |> AsyncSeq.choose stdoutOrStatus //Write out to console
                |> AsyncSeq.fold (|||) ErrorStatus.Okay
            stdoutL Progress <| consoleN "Completed: %O" DateTime.Now
            //Final Error Summary
            if es = ErrorStatus.Okay then
                stdout <| consoleN "All Clear%s." (emoji " 😃")
            else
                let scream = emoji " 😱"
                let frown = emoji " 😦"
                stdout <| consoleN "Found Error(s)%s: %A" (if es <= ErrorStatus.GradeB then frown else scream) es
            return int es
    }