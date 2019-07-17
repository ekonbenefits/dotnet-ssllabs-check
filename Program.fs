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



[<EntryPoint>]
let main argv =
    use app = new CommandLineApplication(Name = "ssllabs-check", 
                                         FullName = "dotnet-ssllabs-check",
                                         Description = "Unofficial SSL Labs Client")
    app.HelpOption() |> ignore;
    let optVersion = app.Option<bool>("-v|--version", 
                                    "Show version and service info only", 
                                    CommandOptionType.NoValue)

    let optOutDir = app.Option<string>("-o|--output <DIRECTORY>", 
                                       "Optional Output Directory for json data [Default: doesn't write out data]",
                                       CommandOptionType.SingleValue)

    let optEmoji = app.Option<bool>("--emoji", 
                                    "Use emoji's when outputing to console", 
                                    CommandOptionType.NoValue)
    
    let hosts = app.Argument<string>("host(s)", "Hosts to check SSL Grades and Validity", multipleValues=true)
   
  
    app.OnValidate(Func<ValidationContext, ValidationResult>(
                         fun c -> 
                            if not <| optVersion.HasValue() && not <| hosts.Values.Any() then
                                ValidationResult("At least one <host> argument is required.")
                            else
                                ValidationResult.Success
                            
                    )) |> ignore

    app.OnExecute(Func<int>(
                    fun ()->
                       hosts.Values
                       |> Check.sslLabs {
                                OptOutputDir = (optOutDir |> OptionToOption)
                                Emoji = optEmoji.HasValue()
                                VersionOnly = optVersion.HasValue()
                            }
                       |> Async.RunSynchronously
                    ))

    app.Execute(argv)
