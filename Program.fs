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
open System
open System.ComponentModel.DataAnnotations
open System.Linq
open McMaster.Extensions.CommandLineUtils

let OptionToOption (opt:CommandOption<'T>) =
    if opt.HasValue() then
        opt.ParsedValue |> Some
    else
        None

let validator (f:Validation.IOptionValidationBuilder<_>->'b) : Validation.IOptionValidationBuilder<_> -> unit =
    fun x -> f x |> ignore

[<EntryPoint>]
let main argv =
    use app = new CommandLineApplication(Name = "ssllabs-check", 
                                         FullName = "dotnet-ssllabs-check",
                                         Description = "Unofficial SSL Labs Client")
    app.HelpOption() |> ignore;

    let optVersion = app.Option<bool>("-v|--version", 
                                    "Show version and service information", 
                                    CommandOptionType.NoValue)

    let optOutDir = app.Option<string>("-o|--output <DIRECTORY>", 
                                       "Output directory for json data [Default: does not write out data]",
                                       CommandOptionType.SingleValue)

    let optHostFile = app.Option<string>("--hostfile <PATH>", 
                                    "Retreive list of hostnames from file to check (one host per line, # preceding comments)", 
                                    CommandOptionType.SingleValue)
                         .Accepts(validator(fun x-> x.ExistingFile()))

    let optVerbose = app.Option<string>("--verbosity <LEVEL>", 
                         "Level of data written to the console (error,warn,info,progress,debug,trace) [default: progress]", 
                         CommandOptionType.SingleValue)
                         .Accepts(validator(fun x-> x.Values(true,"error","warn","info","progress","debug","trace")))
    let optAPI = app.Option<string>("--api <API>", 
                       "Alternative API endpoint (ie. preproduction: https://api.dev.ssllabs.com/api/v3/)", 
                       CommandOptionType.SingleValue)
    let optEmoji = app.Option<bool>("--emoji", 
                                    "Show emoji when outputing to console", 
                                    CommandOptionType.NoValue)
    
    let hosts = app.Argument<string>("hostname(s)", "Hostnames to check SSL Grades and Validity", multipleValues=true)   
  
    app.OnValidate(
        fun _ -> 
            if not <| optVersion.HasValue() 
                    && not <| hosts.Values.Any() 
                    && not <| optHostFile.HasValue() then
                ValidationResult("At least one <hostname> argument or the --hostfile flag is required.")
            elif hosts.Values.Any() 
                    && optHostFile.HasValue() then
                ValidationResult("If using the --hostfile flag  don't include <hostname> arguments.")
            else
                ValidationResult.Success
        ) |> ignore

    app.OnExecute(
        fun ()->
            Check.sslLabs {
                    OptOutputDir = optOutDir |> OptionToOption
                    Emoji = optEmoji.HasValue()
                    VersionOnly = optVersion.HasValue()
                    Hosts = hosts.Values
                    HostFile = optHostFile |> OptionToOption
                    Verbosity = optVerbose |> OptionToOption
                    API = optAPI |> OptionToOption
                }
            |> Async.RunSynchronously
        )

    app.Execute(argv)
