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
open System.Collections.Concurrent
open FSharp.Control
open FSharp.Data
open FSharp.Interop.Compose.Linq
open FSharp.Interop.NullOptAble
open FSharp.Interop.NullOptAble.Operators

module Hdr = FSharp.Data.HttpRequestHeaders

type SslLabsHost = JsonProvider<"samples/host.json">
type SslLabsInfo = JsonProvider<"samples/info.json">

type IJsonDocument = FSharp.Data.Runtime.BaseTypes.IJsonDocument

let toIJsonDocOption target : IJsonDocument option =
    target |> Option.map (fun x-> upcast x)

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

let assmVer = System.Reflection.Assembly.GetEntryAssembly().GetName().Version
let userAgent = sprintf "dotnet-ssllabs-check v%O" assmVer

let assessmentTrack = ConcurrentDictionary<string,int>()

let updateAssessmentReq curr max =
    assessmentTrack.AddOrUpdate("max", max, fun _ _ -> max) |> ignore
    assessmentTrack.AddOrUpdate("curr", curr, fun _ _ -> curr) |> ignore

let checkAllowedNewAssessment () =
    let m, max = assessmentTrack.TryGetValue("max")
    let c, curr = assessmentTrack.TryGetValue("cur")
    m && c && curr < max


let parseReq parseF resp =
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
        let! resp = Http.AsyncRequest(baseUrl + api, headers = [Hdr.UserAgent userAgent])
        return parseReq parseF resp
    }

let requestQ parseF api q = async{
        let! resp = Http.AsyncRequest(baseUrl + api, q, headers = [Hdr.UserAgent userAgent])
        return parseReq parseF resp
    }

let failWithHttpStatus status = failwithf "Service Returned Status %i" status

//Check host list against SSLLabs.com
let sslLabs (config: SslLabConfig) (hosts:string seq) =
    //Configure if showing emoji
    let emoji s = if config.Emoji then s else String.Empty
    if config.Emoji then
        Console.OutputEncoding <- System.Text.Encoding.UTF8

    let writeJsonOutput (fData:IJsonDocument option) identifier =
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
                consoleN "%s - Unofficial Client - (engine:%s) (criteria:%s)" userAgent i.EngineVersion i.CriteriaVersion
                consoleN ""
                for m in i.Messages do
                    consoleN "%s" m
                    consoleN ""
                consoleN "Started: %O" DateTime.Now
                consoleN ""
                if i.MaxAssessments <= 0 then
                    consoleN "Service is not allowing you to request new assessments."
                i.NewAssessmentCoolOff,i.CurrentAssessments,i.MaxAssessments
            | None -> 
                consoleN "%s - Unofficial Client - service unavailable" userAgent
                failWithHttpStatus info.Status
        updateAssessmentReq cur1st max1st

        //If output directory specified, write out json data.
        do! writeJsonOutput (info.Data |> toIJsonDocOption) "info"

        //Function for polling data for a sigle host
        let rec polledData startQ i host= asyncSeq {
            do! Async.Sleep <| newCoolOff * i
            if not <| checkAllowedNewAssessment () then
                yield! polledData startQ i host
            else
                let! analyze = requestQ SslLabsHost.Parse "/analyze" <| ["host", host; "all", "done"] @ startQ
                match analyze.Data with
                | Some data ->
                    let status = parseSslLabsError data.Status
                    match status with
                        | Error -> 
                              let statusMessage = data.JsonValue.Item("statusMessage").ToString()
                              failwithf "Error Analyzing %s - %s" host statusMessage
                        | Ready -> yield data
                        | Dns -> 
                            do! Async.Sleep prePolling
                            yield! polledData [] 0 host
                        | InProgress -> 
                            do! Async.Sleep inProgPolling
                            yield! polledData [] 0 host
                | None ->
                    let random = Random()
                    match analyze.Status with
                    | HttpStatusCodes.TooManyRequests ->
                        yield! polledData startQ i host
                    | HttpStatusCodes.ServiceUnavailable  -> 
                        let delay = random.Next(15_000, 30_000)
                        consoleN "Service Unavailable trying again for '%s' in %O." host
                            <| TimeSpan.FromMilliseconds(float delay)
                        do! Async.Sleep <| delay
                        yield! polledData startQ i host
                    | 529 (* overloaded *)  -> 
                        let delay = random.Next(30_000, 45_000)
                        consoleN "Service Unavailable trying again for '%s' in %O." host
                            <| TimeSpan.FromMilliseconds(float delay)
                        do! Async.Sleep <| delay
                        yield! polledData startQ i host
                    | x -> failWithHttpStatus x
        }

        let! es =
            asyncSeq {
                
                for host in hosts do
                    
                    try 
                        let oldPos = Console.CursorLeft, Console.CursorTop
                        let startTime = DateTime.UtcNow
                        consoleN "%s ..." host
                        Console.SetCursorPosition(oldPos)
                        let! finalData = polledData ["startNew","on"] 1 host |> AsyncSeq.tryFirst
                        consoleN "%s (%O): " host (DateTime.UtcNow - startTime)

                        //If output directory specified, write out json data.
                        do! writeJsonOutput (finalData |> toIJsonDocOption) host
                            
                        //Check a single Host and bitwise OR error codes.
                        let hostCheck (fData: SslLabsHost.Root option) =  
                            chooseSeq {
                                let! data = fData
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

                            }

                        let hostEs = finalData |> hostCheck  |> Seq.fold (|||) ErrorStatus.Okay
                        //Error Summary
                        if hostEs <> ErrorStatus.Okay then
                            consoleN "  Has Error(s): %A" hostEs
                        //SSL Labs link
                        consoleN "  Details:"
                        consoleColorN ConsoleColor.DarkBlue "    https://www.ssllabs.com/ssltest/analyze.html?d=%s" host
                        consoleN ""
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
                                        printExn singleEx.InnerException
                        printExn ex
                        consoleN ""
                        yield ErrorStatus.ExceptionThrown
            } |> AsyncSeq.fold (|||) ErrorStatus.Okay
        //Final Error Summary
        consoleN "Completed: %O" DateTime.Now
        if es = ErrorStatus.Okay then
            consoleN "All Clear%s." (emoji " 😃")
        else
            let scream = emoji " 😱"
            let frown = emoji " 😦"
            consoleN "Found Error(s)%s: %A" (if es <= ErrorStatus.GradeB then frown else scream) es
        return int es
    }