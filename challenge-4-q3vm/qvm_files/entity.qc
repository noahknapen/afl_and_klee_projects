// myscript.qc

float my_entity;

void() my_entity_spawn =
{
    // This function is called when the entity is spawned

    // Print a message to the console
    dprint("My entity has been spawned!\n");
};

void() my_entity_touch =
{
    // This function is called when the entity is touched by the player

    // Print a message to the console
    dprint("Player touched my entity!\n");
};

void() my_entity =
{
    // This function is called to initialize the entity

    // Set the model for the entity (you can replace "progs/player.mdl" with another model)
    self.model = "progs/player.mdl";

    // Set the spawn function for the entity
    self.think = my_entity_spawn;

    // Set the touch function for the entity
    self.touch = my_entity_touch;
};

void() my_entity_init =
{
    // This function is called to initialize the entity at map load

    // Create the entity at coordinates (0, 0, 0)
    my_entity = spawn();
    my_entity.origin = '0 0 0';

    // Call the spawn function immediately (since the entity is already spawned)
    my_entity_spawn();
};

// Register the my_entity_init function to be called at map load
void() precache =
{
    my_entity_init();
};

