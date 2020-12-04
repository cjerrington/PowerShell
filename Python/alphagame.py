import random, string, os, platform

def get_letter(length):
    # generates a random letter
    letters = string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def say(phrase):
    # Uses the systems speech command to say the phrase
    if platform.system() == "Windows":
        speaker = win32com.client.Dispatch("SAPI.SpVoice")
        speaker.Speak(phrase)
    if platform.system() == "Linux":
        os.system(f"spd-say --wait '{phrase}'")

while True:
    letter = get_letter(1)
    assignment = f"Press the letter {letter}: "

    # Speak assignment
    say(assignment)
    guess = str(input(assignment))
    if guess.isalpha():
        if guess.lower() == letter.lower():
            print(f"Great! You pressed the letter {letter}")
            say(f"Great! You pressed the letter {letter}")
        else:
            print(f"You pressed {guess}. You should have pressed {letter}")
            say(f"You pressed {guess}. You should have pressed {letter}")
    else:
        print("You did not choose a letter.")
        say("You did not choose a letter.")
