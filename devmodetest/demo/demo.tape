Output demo2.mp4

Require echo
Require goal
Require jq
Require head
Require tail
Require cut

Set FontSize 22
Set Width 1280
Set Height 720
Set Padding 20
Set LoopOffset 0%

# BEGIN image-frame settings
#Set MarginFill "#79B8C3"
Set MarginFill dark_1280x720.png
Set MarginSize 40
Set WindowBar Colorful
Set WindowBarSize 40
Set CornerRadius 10
# END

Hide
Type "PS1='\033[33m$\033[0m '"
Enter
Ctrl+L
Show

# Time at the beginning for the introduction
Sleep 10s

#
# Introduction - moved to video editor
#

#Type "#   This is DevMode." Sleep 1s
#Type@250ms ".."
#Type " Enhanced" Sleep 1s Enter
#Enter

Type "#   Start a DevMode enabled network." Sleep 500ms Enter
Enter

#
# Create network, store accounts in variables
#
Type@20ms "goal network create \"        Enter
Type@20ms "    --rootdir devmode_test \" Enter
Type@20ms "    --devMode \"              Enter
Type@20ms "    --start"                  Sleep 1s Enter

Sleep 6s

Type@150ms 'clear' Sleep 250ms Enter

Type "#   A DevMode network is now running."                     Enter 2
Type "#   🚧  Quick detour to setup our environment. 🚧 "        Enter
Type@5ms "export ALGORAND_DATA=./devmode_test/Node"              Enter
Type@5ms "TOKEN=$(cat $ALGORAND_DATA/algod.token)"               Enter
Type@5ms "ADDR=$(cat $ALGORAND_DATA/algod.net)"                  Enter
Type@5ms "ACCOUNT_1=$(goal account list | head -n 1 | cut -f 2)" Enter
Type@5ms "ACCOUNT_2=$(goal account list | tail -n 1 | cut -f 2)" Enter
Type "#   🚧  All done. 🚧 "                                     Enter 2

Sleep 2s

#
# Send an illegal transaction, highlight the failure
#
Type@150ms 'clear'                                    Sleep 250ms Enter
Type "#   Time to do something illegal."              Enter
Type "#   Sign a transaction with the wrong account." Enter 2
Sleep 2s

Type@9ms 'goal clerk send \'                               Enter
Type@9ms '   --amount 10000000 \'                          Enter
Type@9ms '   --from   $ACCOUNT_1 \'                        Enter
Type@9ms '   --to     $ACCOUNT_1 \'                        Enter
Type@9ms '   --signer $ACCOUNT_2 # ⚠️⚠️  wrong account ⚠️⚠️ '

Sleep 2s
Enter 2
Sleep 2s

Type '#   Algod correctly rejects the transaction.'        Enter
Type '#   It is signed with the wrong account so the'      Enter
Type '#   error contains "should have been authorized by"' Enter

Sleep 2s

#
# Use the new flag.
#
Type@150ms 'clear' Sleep 250ms Enter
Type "#   Try that again using the --skip-validation flag." Sleep 250ms Enter
Type "#   This is new, can you guess what it does?"         Sleep 250ms Enter 2

Type@9ms 'goal clerk send \'         Enter
Type@9ms '    --amount 10000000 \'   Enter
Type@9ms '    --from   $ACCOUNT_1 \' Enter
Type@9ms '    --to     $ACCOUNT_1 \' Enter
Type@9ms '    --signer $ACCOUNT_2 \' Enter
Type@9ms '    --skip-validation'

Sleep 1s
Enter 2

Sleep 4s
Type "#   Our illegal transaction is committed! 🎉  🎉  🎉 " Enter
Type "#   Let's dump the transaction to see how it works."   Enter 2

Type@9ms 'goal clerk send \'         Enter
Type@9ms '    --amount 10000000 \'   Enter
Type@9ms '    --from   $ACCOUNT_1 \' Enter
Type@9ms '    --to     $ACCOUNT_1 \' Enter
Type@9ms '    --skip-validation \'   Enter
Type@9ms '    --out illegal.txn'

Enter 2
Sleep 1s

Type "msgpacktool -d < illegal.txn " Sleep 250ms Enter
Type "#   Do you see it?" Sleep 2s Enter 2

Type@9ms "msgpacktool -d < illegal.txn | \" Enter
Type@9ms "    jq '{txn: {dev_mode_options: .txn.dev_mode_options}}'"
Enter 2
Sleep 1s

Type "#   This is a new DevMode-only field sent to the evaluator."      Enter
Type "#   By putting configuration in the transaction everything is"    Enter
Type "#   transparent and on-chain. Development tools like private"     Enter
Type "#   block explorers can see what happened."                       Enter 2
Type "#   Like rekeying these fields apply to any transaction type."    Enter 2

Sleep 3s
Type@150ms 'clear' Sleep 250ms Enter

Type "#   This pattern works nicely for other features as well." Enter 2
Type "#   For example, the new --set-block-time parameter."    Enter 2

Sleep 2s

Type@9ms "goal clerk send \"               Enter
Type@9ms "    --amount 10000000 \"         Enter
Type@9ms "    --from   $ACCOUNT_1 \"       Enter
Type@9ms "    --to     $ACCOUNT_1 \"       Enter
Type@9ms "    --set-block-time 123456789 # ⚠️⚠️ remember this number ⚠️⚠️ "

Sleep 1s
Enter 2
Sleep 2s

Type '#   We can look at the new block to see if it worked." Enter 2

Type@9ms 'curl -sq -H "Authorization: Bearer $TOKEN" \'              Enter
Type@9ms '                                  "$ADDR/v2/blocks/2" | \' Enter
# No escapes?
Type@9ms '    perl -pe "system '
Type@9ms                      "'sleep .1'"
Type@9ms                                '"'
Sleep 1500ms Enter 3
Sleep 4500ms

Type "#   That was the 'ts' field in the block header along with the" Enter
Type "#   the new DevMode field in a payment transaction."            Enter 2

Type@150ms 'clear' Sleep 250ms Enter

Type "#   We're wrapping up soon, just a couple more things." Enter
Type "#   All transaction types can set these fields, here is an ASA create..." Enter 2

Type@9ms 'goal asset create \'           Enter
Type@9ms '   --creator $ACCOUNT_1 \'     Enter
Type@9ms '   --total   1 \'              Enter
Type@9ms '   --name    "DevMode NFT" \'  Enter
Type@9ms '   --set-block-time 999999999'

Sleep 1
Enter 2
Sleep 2

Type "#   Check that the new block timestamp is 999999999..." Enter 2
Type@9ms 'curl -sq -H "Authorization: Bearer $TOKEN" \' Enter
Type@9ms '                                  "$ADDR/v2/blocks/3" | \' Enter
Type@9ms '                    grep "\"ts\""'                         Enter 2

Type@150ms 'clear' Sleep 250ms Enter
