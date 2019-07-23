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
module SslLabs

open System
open System.IO
open FSharp.Control
open FSharp.Data
open FSharp.Interop.Compose.Linq
open FSharp.Interop.Compose.System
open FSharp.Interop.NullOptAble
open FSharp.Interop.NullOptAble.Operators
open Console
open Json

module Hdr = FSharp.Data.HttpRequestHeaders
type Host = JsonProvider<"samples/host.json">
type Info = JsonProvider<"samples/info.json">

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

type Error = 
    Ready
    | Dns
    | InProgress
    | Error

let parseSslLabsError = 
    function | "READY" -> Ready 
             | "DNS" -> Dns 
             | "IN_PROGRESS" -> InProgress 
             | _ -> Error

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
let hostJsonProcessor (queries: string seq) (data: Host.Root option)  =  
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
                yield AddStatus Status.CertIssue
            //Check Expiration of Cert
            let status, color, label =
                if expireSpan <=TimeSpan.FromDays 0.0 then
                    Status.Expired, ConsoleColor.DarkRed, "Expired"
                elif expireSpan <= warningSpan then
                    Status.Expiring, ConsoleColor.DarkYellow, "Expires"
                else
                    Status.Okay, ConsoleColor.DarkGreen, "Expires"
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
                | Grade "A" -> Status.Okay, ConsoleColor.DarkGreen
                | Grade "B" -> Status.GradeB, ConsoleColor.DarkYellow
                | _ -> Status.NotGradeAOrB, ConsoleColor.DarkRed
            yield console "    Grade: "
            yield consoleColorN color "%s" ep.Grade
            yield AddStatus status
        //Add JsonPath Queries to output if any
        if queries |> Seq.isEmpty |> not  then
            let newtonJson = Newtonsoft.Json.Linq.JObject.Parse (data'.JsonValue.ToString())
            let queryResults =
                chooseSeq {
                    for q in queries do
                        let! result = newtonJson |> queryJmesPath q
                        let level = Console.getLevel result
                        let status, color = 
                            match level with
                            | Level.Warn ->
                                Status.QueriedWarn, ConsoleColor.DarkYellow
                            | Level.Error ->
                                Status.QueriedError, ConsoleColor.DarkRed
                            | _ -> //any other levels don't effect error status, nor make sense colored
                                Status.Okay, originalColor
                        yield! chooseSeq {
                            yield consoleN "'%s':" q
                                |> indent 4
                                |> includeLevel level
                            yield consoleColorN color "%O" result
                                |> indent 6
                                |> includeLevel level
                            yield AddStatus status
                                |> includeLevel level
                        }
                }
            if queryResults |> Seq.isEmpty |> not then
                let level = queryResults |> Seq.choose (function|IncludedLevel(l,_)-> Some l|_->None) |> Seq.min
                yield consoleN "Queried Data:" |> indent 2 |> includeLevel level
                yield! queryResults
        }
//Check host list against SSLLabs.com
type Config = { 
                        OptOutputDir:  string option
                        Emoji:         bool
                        VersionOnly:   bool
                        Hosts:         string seq
                        Verbosity:     string option
                        API:           string option
                        Queries:       string seq
                        LogWrite:      ConsoleColor -> string -> unit
                    }
let check (config: Config) =
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
    let verboseLevel = defaultArg (config.Verbosity |> Option.map parseConsoleError) Level.Progress
    let rec levelFilter level result = 
        match result with
            | IncludedLevel(level', result') -> levelFilter level' result'
            | _ -> if level <= verboseLevel then result else NoOp

    let stdout = stdoutOrStatusBy config.LogWrite None >> ignore //Always Print
    let stdoutL level = stdoutOrStatusBy config.LogWrite (Some {|Verbosity= verboseLevel; DefaultLevel = level|}) >> ignore
    let stdoutOrStatus = stdoutOrStatusBy config.LogWrite None //Always Print



    let writeJsonOutput (fData:IJsonDocument option) identifier =
        let asyncNoOp = lazy Async.Sleep 0
        option {
                let! data = fData
                let! outDir = config.OptOutputDir
                Directory.CreateDirectory outDir |> ignore
                let outPath = Path.Combine(outDir, sprintf "%s.json" identifier)
                                |> Path.GetFullPath
                stdoutL Level.Trace <| consoleN "%O Writing out json data to %s" DateTime.Now outPath
                return File.WriteAllTextAsync(outPath, data.JsonValue.ToString()) |> Async.AwaitTask
        } |?-> asyncNoOp

    //Main Logic
    async {
        //Print out SSL Labs Info
        let! info = request' Info.Parse "/info"
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
  
        //force parse check
        do config.Queries |> Seq.iter (jmes.Parse >> ignore)

        if config.API |> Option.isSome then
            stdoutL Level.Info  <| consoleNN "API: %s" baseUrl
        guard {
            let! outDir = config.OptOutputDir
            stdoutL Level.Info  <| consoleNN "JSON Output Directory: %s" (outDir |> Path.GetFullPath)
        }
        if config.VersionOnly then
            stdoutL Level.Info  <| consoleNN "Assessments Available %i of %i" cur1st max1st
            return Status.Okay
        else
            stdoutL Level.Progress <| consoleNN "Started: %O" DateTime.Now
            stdout  <| consoleN "Hostnames to Check:"
            for host in config.Hosts do
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
                        stdoutL Level.Trace
                            <| consoleN "%O Waiting For Assesment Slot '%s'#%i (Available: %i/%i)"
                                   DateTime.Now state.Host state.Index check.Current check.Max
                        do! Async.sleepTimeSpan inProgPolling
                        yield! pollUntilData state
                    else 
                        if newAssess then
                            stdoutL Level.Debug
                                <| consoleN "%O ATTEMPT New Req '%s'#%i (Reqs/Max: %i/%i)"
                                    DateTime.Now state.Host state.Index check.Current check.Max
                        let! analyze = requestQ' Host.Parse "/analyze"
                                            <| ["host", state.Host; "all", "done"] @ state.StartQ
                        match analyze.Data with
                        | Some data ->
                            if newAssess then
                                stdoutL Level.Debug
                                    <| consoleN "%O STARTED New Req '%s'#%i (Reqs/Max: %i/%i)"
                                        DateTime.Now state.Host state.Index check.Current check.Max
                            let status = parseSslLabsError data.Status
                            stdoutL Level.Trace
                                <| consoleN "%O POLL for '%s' (Reqs/Max: %i/%i) (HttpStatus:%i) (Status:%A)"
                                    DateTime.Now state.Host analyze.Current analyze.Max analyze.Status status
                            let stateForPolling = {|state with StartQ = List.empty; Index = 0|}
                            match status with
                                | Ready ->
                                    yield data
                                | Error -> 
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
                            stdoutL Level.Debug
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
                                stdoutL Level.Info 
                                    <| consoleNN "Service Unavailable trying again for '%s' in %O." state.Host delay 
                                do! Async.sleepTimeSpan delay
                                yield! pollUntilData state
                            | 529 (* overloaded *)  -> 
                                let delay = serviceOverloadedPolling ()
                                //Write out Immediately
                                stdoutL Level.Info
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
                    let hostResults = data |> hostJsonProcessor config.Queries
                    let hostEs = 
                         hostResults
                         |> Seq.map extractStatus
                         |> Seq.fold (|||) Status.Okay

                    let mark = match hostEs with | Status.Okay -> emoji "✔" 
                                                 | x when x < Status.Warn -> emoji "⚠️"
                                                 | _ -> emoji "❌"

                    let hostLevel = levelForStatus hostEs
                    yield levelFilter hostLevel
                           <| consoleN "%s%s: " host mark
                    //this intentionally supresses exit status for warning level status if verbosity=Error
                    yield! hostResults |> Seq.map (levelFilter hostLevel) |> AsyncSeq.ofSeq
                    //Error Summary
                    if hostEs <> Status.Okay then
                         yield levelFilter hostLevel
                               <| consoleN "  Has Error(s): %A" hostEs
                    //SSL Labs link
                    yield levelFilter hostLevel
                           <| consoleN "  Details:"
                    yield levelFilter hostLevel
                           <| consoleColorNN ConsoleColor.Blue "    %s?d=%s" appUrl host
                with ex -> 
                    yield consoleN "%s❌: " host
                    yield consoleN "%s (Unexpected Error):" host
                    yield consoleN "  Has Error(s): %A" Status.ExceptionThrown
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
                    yield AddStatus Status.ExceptionThrown
                }
            let startTime = DateTime.UtcNow
            let totalHosts = config.Hosts |> Seq.length
            let! es = 
                config.Hosts
                |> Seq.indexed
                |> AsyncSeq.ofSeq
                |> AsyncSeq.map parallelProcessHost
                |> AsyncSeq.mapAsyncParallelUnordered AsyncSeq.toListAsync
                |> AsyncSeq.indexed
                |> AsyncSeq.map (
                    fun (i, tail) ->
                            (levelFilter Level.Progress
                                <| consoleN "-- %d of %i --- %O --" (i+1L) totalHosts (DateTime.UtcNow - startTime)
                            ) :: tail
                    )
                |> AsyncSeq.collect AsyncSeq.ofSeq
                |> AsyncSeq.choose stdoutOrStatus //Write out to console
                |> AsyncSeq.fold (|||) Status.Okay
            stdoutL Level.Progress <| consoleN "Completed: %O" DateTime.Now
            //Final Error Summary
            if es = Status.Okay then
                stdout <| consoleN "All Clear%s." (emoji " 😃")
            else
                let scream = emoji " 😱"
                let frown = emoji " 😦"
                stdout <| consoleN "Found Error(s)%s: %A" (if es < Status.Warn then frown else scream) es
            return es
    }