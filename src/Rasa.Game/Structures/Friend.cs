﻿namespace Rasa.Structures
{
    using Memory;

    public class Friend : IPythonDataStruct
    {
        public ulong CharacterId { get; set; }
        public uint UserId { get; set; }
        public string CharacterName { get; set; }
        public string FamilyName { get; set; }
        public uint Level { get; set; }
        public uint ContextId { get; set; }
        public bool IsOnline { get; set; }
        
        public Friend()
        {
        }

        public Friend(CharacterEntry character, string familyName)
        {
            CharacterId = character.Id;
            UserId = character.AccountId;
            CharacterName = character.Name;
            FamilyName = familyName;
            Level = character.Level;
            ContextId = character.MapContextId;
            IsOnline = character.IsOnline;
        }

        public void Read(PythonReader pr)
        {
        }

        public void Write(PythonWriter pw)
        {
            pw.WriteList(7);
            pw.WriteULong(CharacterId);
            pw.WriteUInt(UserId);
            pw.WriteUnicodeString(CharacterName);
            pw.WriteUnicodeString(FamilyName);
            pw.WriteUInt(Level);
            pw.WriteUInt(ContextId);
            pw.WriteBool(IsOnline);
        }
    }
}