module Console

open System
open System.IO
open System.Text
open FSharp.Interop.Compose.System
open FSharp.Interop.NullOptAble
open DevLab.JmesPath.Functions
open Newtonsoft.Json
open Newtonsoft.Json.Linq


[<Flags>]
type Status = Okay = 0 
                   | Expiring = 1 
                   | GradeB = 2 
                   | CertIssue = 4 
                   | QueriedWarn = 8
                   // Gap to add More Warnings in the future
                   | Warn = 512 // Warn is < Warn
                   | Error = 1024 // Error is > Error
                   | NotGradeAOrB = 2048 
                   | Expired = 4096 
                   | ExceptionThrown = 8192
                   | QueriedError = 16384

[<RequireQualifiedAccess>]
type Level = 
    Error
    | Warn
    | Info
    | Progress
    | Debug
    | Trace

let parseConsoleError = 
    String.toLower >>
    function | "error" -> Level.Error 
             | "warn" -> Level.Warn
             | "trace" -> Level.Trace 
             | "debug" -> Level.Debug
             | "progress" -> Level.Progress 
             | _ -> Level.Info

let levelForStatus status =
    if status = Status.Okay then
        Level.Info
    elif status <= Status.Warn then
        Level.Warn
    else
        Level.Error

//Setup Console initial state and functions
let originalColor = Console.ForegroundColor
type ResultStream =
    | NoOp
    | ConsoleColorText of string * ConsoleColor
    | AddStatus of Status
    | IncludedLevel of Level * ResultStream
let private consoleStreamWriter (lineEnd:string) (color:ConsoleColor) fmt =
    let write (s:string) =
        ConsoleColorText(s + lineEnd, color)
    Printf.kprintf write fmt

let includeLevel level result = IncludedLevel (level, result)

let consoleN fmt = consoleStreamWriter Environment.NewLine originalColor fmt
let consoleNN fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine) originalColor fmt 
let console fmt = consoleStreamWriter String.Empty originalColor fmt 
let consoleColorN color fmt = consoleStreamWriter Environment.NewLine color fmt 
let consoleColorNN color fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine) color fmt 

let consoleColor color fmt = consoleStreamWriter String.Empty color fmt 
let private consoleMonitor = obj()

let lockingWrite color (text:string) =
    lock(consoleMonitor) (
        fun () ->
            Console.ForegroundColor <- color
            Console.Write(text)
            Console.ForegroundColor <- originalColor
    )

let rec stdoutOrStatusBy (write:ConsoleColor -> string -> unit) (by:{|Verbosity:Level; DefaultLevel:Level|} option) (result:ResultStream) =
    match result with
    | ConsoleColorText(s, color) ->
        let display =
            match by with
            | Some by' -> by'.DefaultLevel <= by'.Verbosity 
            | None -> true
        if display then
            s |> write color
        None
    | AddStatus e -> Some e
    | NoOp  -> None
    | IncludedLevel (level, result) -> stdoutOrStatusBy write (option{ let! by' = by
                                                                       return {|by' with Verbosity = level|} }) result

//Not tail recursive, but should be fine
let rec indent (spaces: int) result =
    match result with
    | ConsoleColorText(text, color) ->
        use reader = new StringReader(text)
        let sb = StringBuilder()
        while reader.Peek() > -1 do
            let read = reader.ReadLine()
            sb.AppendLine(sprintf "%s%s" (String.replicate spaces " ") read) |> ignore
        ConsoleColorText(sb.ToString(), color)
    | IncludedLevel (level', result') -> IncludedLevel(level', indent spaces result')
    | x -> x

[<AbstractClass>]
type JmesLevelFunction (name, level) = 
    inherit JmesPathFunction (name, 1) //Defined to have 1 argument
    let addLevel (level:Level) (tok:JToken) =
        let tok' = tok.DeepClone()
        tok'.AddAnnotation(level)
        tok'
    override __.Execute([<ParamArray>]args:JmesPathFunctionArgument[]) : JToken= 
        args |> Array.head |> (fun x -> x.Token |> addLevel level )

type Error() = inherit JmesLevelFunction ("error", Level.Error)
type Warn() = inherit JmesLevelFunction ("warn", Level.Warn)
type Info() = inherit JmesLevelFunction ("info", Level.Info)
type Progress() = inherit JmesLevelFunction ("progress", Level.Progress)
type Debug() = inherit JmesLevelFunction ("debug", Level.Debug)
type Trace() = inherit JmesLevelFunction ("trace", Level.Trace)

let getLevel (tok:JToken) =
    let annotes = tok.Annotations<Level>()
    if annotes |> Seq.isEmpty then
        Level.Info
    else
        annotes |> Seq.min